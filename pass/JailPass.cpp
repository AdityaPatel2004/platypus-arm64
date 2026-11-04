//===- JailPass.cpp - AArch64 execution-jail clamp for indirect calls -----===//
//
// An out-of-tree LLVM 20 pass. Before every *indirect* call/invoke it clamps
// the target pointer into the calling module's own address range, so a
// hijacked function pointer cannot leave this module (cannot reach system()/
// execve() in libc). Direct calls (including PLT calls) are untouched.
//
// Two enforcing clamp encodings (Research Question 2):
//
//  mask  (Option B, PLaTypus-style or/and masks loaded from memory)
//      ldr  xo, [__jail_masks]      ; ormask  = window base B (2^k aligned)
//      ldr  xa, [__jail_masks+8]    ; andmask = B | (2^k-1)
//      orr  xt, xt, xo
//      and  xt, xt, xa
//      blr  xt
//    The masks live on their own 64 KiB page, filled by the runtime
//    constructor (runtime/jail_rt.c) and then made READ-ONLY with mprotect.
//    (Intel PLaTypus also loads its masks from memory - `or rax,[rip+ormask]`
//    - but x86 can fold the load into the or/and; AArch64 is load/store, so the
//    same clamp is 4 instructions instead of 2.)
//
//  pcrel (Option D, base-relative, nothing stored at all)
//      adrp x16, __ehdr_start        ; module base, computed from the PC
//      sub  xt, xt, x16
//      and  xt, xt, #(2^k-1)         ; a run of ones = a legal AArch64 immediate
//      add  xt, xt, x16
//      blr  xt
//    Window = [module base, base + 2^k). k comes from JAIL_K at compile time
//    (default 22 = 4 MiB) and is checked against the real module size by the
//    runtime at start-up (abort if the module does not fit).
//
//  aligned (Option C, NaCl-style aligned jail, placed by the kernel)
//      adrp x16, __ehdr_start        ; module base (hoistable, off the data path)
//      and  x16, x16, #~(2^k-1)      ; aligned block base (hoistable)
//      bfxil x16', xt, #0, #k        ; or: and xt,#(2^k-1) ; orr xt,xt,x16
//      blr  xt
//    The executable is linked with -z max-page-size=2^k, so every PT_LOAD has
//    p_align = 2^k and Linux (>= 5.10; glibc >= 2.35 for shared libraries)
//    places the module on a 2^k boundary. No custom loader is needed. The
//    trade: ASLR keeps (k - 12) fewer bits of entropy for this module.
//    The runtime verifies the module really sits inside the aligned block.
//
// Diagnostic (non-default) modes:
//   check : t' = __jail_check(t)  -> clamps (Option B) and logs every bend.
//   audit : t' = __jail_audit(t)  -> returns t unchanged, counts out-of-jail
//           targets (measures what a program legitimately calls by pointer).
//
// Fake-PLT. Every imported function whose ADDRESS this module takes (stored in
// a table, passed as a callback) gets an in-module stub
//      __jail_tramp_<f>:  bti c ; b <f>
// and the address-takes are redirected to it, so the stored pointer survives
// the clamp while still reaching <f> through a direct branch (via the PLT).
// The stub is two machine instructions in module-level assembly, so it
// forwards ANY signature untouched - including variadic functions such as
// fcntl/open/ioctl/mremap, which an IR `musttail` trampoline cannot forward
// (that limitation made the v2 pass leave them un-stubbed and crashed SQLite on
// every on-disk database). Stubs are COMDAT + weak + hidden, so the copies
// emitted by different source files of one program fold into one.
//
// Mode and knobs come from the environment at compile time (JAIL / JAIL_MODE,
// JAIL_K, JAIL_NO_FAKEPLT, JAIL_FAKEPLT_OUT) because with -fpass-plugin the
// plugin is loaded after clang parses -mllvm options.
//
// Coverage: indirect call/invoke (CallBase), which after code generation are
// `blr` and indirect tail calls `br`. Not covered: computed goto (indirectbr;
// targets are block addresses in the same function), hand-written assembly,
// and objects not compiled through the pass. tools/asm_audit.py checks the
// final binary and reports every unclamped indirect branch.
//===----------------------------------------------------------------------===//
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace llvm;

static std::string envOr(const char *a, const char *b, const char *dflt) {
  if (const char *m = std::getenv(a)) return m;
  if (b) if (const char *m = std::getenv(b)) return m;
  return dflt;
}

namespace {

static bool isIndirect(CallBase *CB) {
  if (CB->isInlineAsm()) return false;
  if (CB->getCalledFunction()) return false;          // direct call (incl. PLT)
  Value *op = CB->getCalledOperand()->stripPointerCasts();
  if (isa<Function>(op)) return false;                // direct through a cast
  return true;
}

// The callee operand of a direct call stays the real function (a PLT call,
// already safe). Every other use (stored in a table, passed as an argument,
// compared) is an address-take that would store a cross-module pointer.
static bool isDirectCalleeUse(const Use &U) {
  if (auto *CB = dyn_cast<CallBase>(U.getUser())) return CB->isCallee(&U);
  return false;
}

static unsigned installFakePlt(Module &M, std::vector<std::string> &names) {
  std::vector<Function *> imports;
  for (Function &G : M) {
    if (!G.isDeclaration() || G.isIntrinsic()) continue;
    StringRef N = G.getName();
    if (N.empty() || N.starts_with("__jail_")) continue;
    bool taken = false;
    for (const Use &U : G.uses())
      if (!isDirectCalleeUse(U)) { taken = true; break; }
    if (taken) imports.push_back(&G);
  }
  std::string asmText;
  unsigned n = 0;
  for (Function *G : imports) {
    std::string N = G->getName().str();
    std::string T = "__jail_tramp_" + N;
    // two-instruction stub in its own COMDAT section: bti c ; b <real>
    asmText += "\t.section .text." + T + ",\"axG\",%progbits," + T + ",comdat\n"
               "\t.p2align 2\n"
               "\t.weak \"" + T + "\"\n"
               "\t.hidden \"" + T + "\"\n"
               "\t.type \"" + T + "\",%function\n"
               "\"" + T + "\":\n"
               "\thint #34\n"   // = bti c, spelled as a hint so any assembler accepts it
               "\tb \"" + N + "\"\n"
               "\t.size \"" + T + "\", .-\"" + T + "\"\n"
               "\t.text\n";
    Function *TF = Function::Create(G->getFunctionType(),
                                    GlobalValue::ExternalLinkage, T, &M);
    TF->setVisibility(GlobalValue::HiddenVisibility);
    TF->setDSOLocal(true);
    TF->setCallingConv(G->getCallingConv());
    G->replaceUsesWithIf(TF, [](Use &U) { return !isDirectCalleeUse(U); });
    names.push_back(N);
    ++n;
  }
  if (!asmText.empty()) M.appendModuleInlineAsm(asmText);
  return n;
}

struct JailPass : PassInfoMixin<JailPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &C = M.getContext();
    Type *I64 = Type::getInt64Ty(C);
    Type *I8 = Type::getInt8Ty(C);

    std::string Mode = envOr("JAIL_MODE", "JAIL", "mask");
    bool mask = Mode == "mask", pcrel = Mode == "pcrel" || Mode == "aligned";
    bool aligned = Mode == "aligned";
    bool check = Mode == "check", audit = Mode == "audit";
    if (!mask && !pcrel && !aligned && !check && !audit) {
      errs() << "[jail] unknown JAIL mode=" << Mode << ", using mask\n";
      mask = true; Mode = "mask";
    }
    unsigned K = (unsigned)std::atoi(envOr("JAIL_K", nullptr, "22").c_str());
    if (K < 12 || K > 40) { errs() << "[jail] JAIL_K out of range, using 22\n"; K = 22; }

    GlobalVariable *masks = nullptr, *ehdr = nullptr;
    FunctionCallee rt;
    if (mask) {
      // [2 x i64] { ormask, andmask } on a read-only-after-init page (jail_rt.c)
      ArrayType *AT = ArrayType::get(I64, 2);
      masks = M.getGlobalVariable("__jail_masks");
      if (!masks) {
        masks = new GlobalVariable(M, AT, false, GlobalValue::ExternalLinkage,
                                   nullptr, "__jail_masks");
        masks->setVisibility(GlobalValue::HiddenVisibility);
        masks->setDSOLocal(true);
      }
    } else if (pcrel) {
      // the linker-defined first byte of this module (ELF header)
      ehdr = M.getGlobalVariable("__ehdr_start");
      if (!ehdr) {
        ehdr = new GlobalVariable(M, I8, true, GlobalValue::ExternalLinkage,
                                  nullptr, "__ehdr_start");
        ehdr->setVisibility(GlobalValue::HiddenVisibility);
        ehdr->setDSOLocal(true);
      }
      // record k so the runtime can verify the module fits in the window
      if (!M.getGlobalVariable("__jail_pcrel_k")) {
        auto *kg = new GlobalVariable(M, I64, true, GlobalValue::WeakODRLinkage,
                                      ConstantInt::get(I64, K), "__jail_pcrel_k");
        kg->setVisibility(GlobalValue::HiddenVisibility);
      }
      if (aligned && !M.getGlobalVariable("__jail_aligned")) {
        auto *ag = new GlobalVariable(M, I64, true, GlobalValue::WeakODRLinkage,
                                      ConstantInt::get(I64, 1), "__jail_aligned");
        ag->setVisibility(GlobalValue::HiddenVisibility);
      }
    } else {
      rt = M.getOrInsertFunction(check ? "__jail_check" : "__jail_audit", I64, I64);
    }

    unsigned nTramp = 0;
    bool enforcing = mask || pcrel || check;
    if (enforcing && !std::getenv("JAIL_NO_FAKEPLT")) {
      std::vector<std::string> names;
      nTramp = installFakePlt(M, names);
      if (const char *out = std::getenv("JAIL_FAKEPLT_OUT"))
        if (FILE *f = fopen(out, "a")) {
          for (auto &s : names) fprintf(f, "%s\n", s.c_str());
          fclose(f);
        }
    }

    // Options C/D: the module base is read with one `adrp` per call site,
    // emitted as side-effecting inline asm. That keeps the whole clamp glued to
    // its call: a pure computation would be hoisted/CSE'd by the optimiser and
    // the clamped pointer could then be spilled to the stack and reloaded right
    // before the call, where a stack-write bug could replace it (seen in an
    // earlier build; tools/asm_audit.py catches it). __ehdr_start is
    // page-aligned (the module's first byte), so adrp alone gives it exactly.
    InlineAsm *adrpBase = InlineAsm::get(FunctionType::get(I64, false),
                                         "adrp $0, __ehdr_start", "=r",
                                         /*hasSideEffects=*/true);
    unsigned nClamped = 0, nFns = 0;
    uint64_t lowMask = (K >= 64) ? ~0ULL : ((1ULL << K) - 1);
    for (Function &F : M) {
      if (F.isDeclaration()) continue;
      ++nFns;
      SmallVector<CallBase *, 8> targets;
      for (Instruction &I : instructions(F))
        if (auto *CB = dyn_cast<CallBase>(&I))
          if (isIndirect(CB)) targets.push_back(CB);
      for (CallBase *CB : targets) {
        IRBuilder<> B(CB);
        Value *t = CB->getCalledOperand();
        Type *pt = t->getType();
        Value *ti = B.CreatePtrToInt(t, I64, "jail.t");
        Value *cl;
        if (mask) {
          Value *orp = B.CreateConstInBoundsGEP2_32(masks->getValueType(), masks, 0, 0);
          Value *anp = B.CreateConstInBoundsGEP2_32(masks->getValueType(), masks, 0, 1);
          Value *orm = B.CreateLoad(I64, orp, "jail.or");
          Value *anm = B.CreateLoad(I64, anp, "jail.and");
          cl = B.CreateAnd(B.CreateOr(ti, orm, "jail.floor"), anm, "jail.ceil");
        } else if (aligned) {
          // (t & (2^k-1)) | (base & ~(2^k-1)): a bit-field insert, one op on
          // the target's dependency chain; base & ~m is loop-invariant
          Value *base = B.CreateCall(adrpBase, {}, "jail.base");
          Value *blk = B.CreateAnd(base, ConstantInt::get(I64, ~lowMask), "jail.blk");
          cl = B.CreateOr(B.CreateAnd(ti, ConstantInt::get(I64, lowMask), "jail.low"),
                          blk, "jail.in");
        } else if (pcrel) {
          Value *base = B.CreateCall(adrpBase, {}, "jail.base");
          Value *off = B.CreateAnd(B.CreateSub(ti, base, "jail.off"),
                                   ConstantInt::get(I64, lowMask), "jail.wrap");
          cl = B.CreateAdd(off, base, "jail.in");
        } else {
          cl = B.CreateCall(rt, {ti}, "jail.chk");
        }
        CB->setCalledOperand(B.CreateIntToPtr(cl, pt, "jail.p"));
        ++nClamped;
      }
    }
    errs() << "[jail] mode=" << Mode << (pcrel ? " k=" + std::to_string(K) : "")
           << " module=" << M.getName() << " functions=" << nFns
           << " indirect-calls-clamped=" << nClamped
           << " fakeplt-trampolines=" << nTramp << "\n";
    bool changed = nClamped || nTramp || pcrel || mask;
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "JailPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // run last, after optimisation/devirtualisation, so what we clamp
            // is exactly the indirect calls that survive into the final code
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
                  MPM.addPass(JailPass());
                });
          }};
}
