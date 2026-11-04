//===- JailPass.cpp - AArch64 execution-jail clamp for indirect calls -----===//
//
// An out-of-tree LLVM 20 pass. Before every *indirect* call/invoke, it clamps
// the target pointer into the module's own address range, so a hijacked
// function pointer cannot leave this module (cannot reach system()/execve() in
// libc). Direct calls (including PLT calls to other libraries) are untouched.
//
// The clamp (mask mode) is, in AArch64 terms:
//     ldr  xmask_or , =__jail_ormask     ; floor  (module base, 2^k aligned)
//     ldr  xmask_and, =__jail_andmask    ; ceiling(base | (2^k-1))
//     orr  xt, xt, xmask_or
//     and  xt, xt, xmask_and
//     blr  xt
// The two mask constants are loaded from module-local globals (Option B) — on
// AArch64 an AND/ORR immediate cannot encode an arbitrary address mask, so the
// Intel two-instruction clamp does not transfer and we load instead. The
// globals are filled at start-up by runtime/jail_rt.c via dl_iterate_phdr.
//
// Modes (from the JAIL / JAIL_MODE environment variable at compile time, read
// by jailMode() below — not an -mllvm flag, see that function's comment):
//   mask  : inline (t|or)&and, replace the call target. Enforcing; benchmarked.
//   check : t' = __jail_check(t)  -> clamps and logs divergence. Loud enforce.
//   audit : t' = __jail_audit(t)  -> returns t unchanged, counts out-of-jail
//           targets. Non-enforcing; used to measure how often the clamp fires.
//
// Coverage: instruments indirect call/invoke (CallBase). Computed goto
// (indirectbr) targets are block addresses within the same function (already
// in-module, not a cross-module escape); hand-written asm is not seen by the
// pass. tools/asm_audit.sh checks the final binary for any blr/br not preceded
// by a clamp, so the uninstrumented count is reported, not assumed zero.
//
//===----------------------------------------------------------------------===//
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

using namespace llvm;

// Mode is read from the environment rather than an -mllvm cl::opt: with
// -fpass-plugin the plugin loads after LLVM parses -mllvm options, so a
// plugin-registered cl::opt is not yet known and clang rejects the flag. The
// a64cc driver already sets JAIL in the environment, which the spawned clang
// inherits, so the pass reads it directly here.
static std::string jailMode() {
  if (const char *m = std::getenv("JAIL_MODE")) return m;
  if (const char *m = std::getenv("JAIL"))      return m;
  return "mask";
}

namespace {

static bool isIndirect(CallBase *CB) {
  if (CB->isInlineAsm()) return false;
  if (CB->getCalledFunction()) return false;      // direct call (incl. PLT)
  Value *op = CB->getCalledOperand()->stripPointerCasts();
  if (isa<Function>(op)) return false;            // direct through a bitcast
  return true;
}

// Is this Use the *callee operand* of a direct call to the function? Those must
// stay as the real function (they are PLT calls, already safe). Any other use
// (storing &G into a table, passing &G as an argument) is an address-take that
// would store a cross-module pointer -> must be redirected to a trampoline.
static bool isDirectCalleeUse(const Use &U) {
  if (auto *CB = dyn_cast<CallBase>(U.getUser()))
    return CB->isCallee(&U);
  return false;
}

// Fake-PLT: for every imported function whose address this module takes, build
// an in-module trampoline that tail-jumps to the real function, and redirect
// the address-takes to it. The stored pointer is then in-module (survives the
// clamp) yet the trampoline still reaches the real libc function via a direct
// (PLT) branch. Returns the number of trampolines built; fills `names`.
static unsigned installFakePlt(Module &M, std::vector<std::string> &names) {
  LLVMContext &C = M.getContext();
  std::vector<Function *> imports;
  for (Function &G : M) {
    if (!G.isDeclaration()) continue;             // only imports (no body here)
    if (G.isIntrinsic()) continue;
    if (G.getName().starts_with("__jail_")) continue;
    if (G.getName().empty()) continue;
    bool addressTaken = false;
    for (const Use &U : G.uses())
      if (!isDirectCalleeUse(U)) { addressTaken = true; break; }
    if (addressTaken) imports.push_back(&G);
  }
  unsigned n = 0;
  for (Function *G : imports) {
    FunctionType *FT = G->getFunctionType();
    if (FT->isVarArg()) {                          // musttail can't forward varargs
      errs() << "[jail] fakeplt: skipping variadic import " << G->getName()
             << " (left un-stubbed)\n";
      continue;
    }
    Function *T = Function::Create(FT, GlobalValue::InternalLinkage,
                                   "__jail_tramp_" + G->getName(), &M);
    // internal linkage is already module-private; keep default visibility
    T->addFnAttr("branch-target-enforcement");    // ensure a BTI landing pad
    T->setCallingConv(G->getCallingConv());
    BasicBlock *BB = BasicBlock::Create(C, "entry", T);
    IRBuilder<> B(BB);
    SmallVector<Value *, 8> args;
    for (Argument &A : T->args()) args.push_back(&A);
    CallInst *call = B.CreateCall(FT, G, args);
    call->setTailCallKind(CallInst::TCK_MustTail);
    call->setCallingConv(G->getCallingConv());
    if (FT->getReturnType()->isVoidTy()) B.CreateRetVoid();
    else                                 B.CreateRet(call);
    // redirect every address-take (not direct calls) to the trampoline
    G->replaceUsesWithIf(T, [](const Use &U) { return !isDirectCalleeUse(U); });
    names.push_back(G->getName().str());
    ++n;
  }
  return n;
}

struct JailPass : PassInfoMixin<JailPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &C = M.getContext();
    Type *I64 = Type::getInt64Ty(C);

    // module-local mask globals, defined (and filled) by jail_rt.o
    auto maskGlobal = [&](StringRef n) -> GlobalVariable * {
      GlobalVariable *g = M.getGlobalVariable(n);
      if (!g) {
        g = new GlobalVariable(M, I64, /*isConstant=*/false,
                               GlobalValue::ExternalLinkage, nullptr, n);
        g->setVisibility(GlobalValue::HiddenVisibility);
      }
      return g;
    };
    GlobalVariable *orG = nullptr, *andG = nullptr;
    FunctionCallee rt;

    std::string Mode = jailMode();
    bool mask  = (Mode == "mask");
    bool check = (Mode == "check");
    bool audit = (Mode == "audit");
    if (!mask && !check && !audit) {
      errs() << "[jail] unknown JAIL mode=" << Mode << ", using mask\n";
      mask = true; Mode = "mask";
    }
    if (mask) { orG = maskGlobal("__jail_ormask"); andG = maskGlobal("__jail_andmask"); }
    else {
      rt = M.getOrInsertFunction(check ? "__jail_check" : "__jail_audit",
                                 I64, I64);
    }

    // Fake-PLT runs first (enforcing modes only): redirect address-taken imports
    // to in-module trampolines so their stored pointers survive the clamp.
    unsigned nTramp = 0;
    bool fakeplt = (mask || check) && !std::getenv("JAIL_NO_FAKEPLT");
    if (fakeplt) {
      std::vector<std::string> names;
      nTramp = installFakePlt(M, names);
      if (const char *out = std::getenv("JAIL_FAKEPLT_OUT")) {
        if (FILE *f = fopen(out, "a"))
          { for (auto &s : names) fprintf(f, "%s\n", s.c_str()); fclose(f); }
      }
    }

    unsigned nClamped = 0, nFns = 0;
    for (Function &F : M) {
      if (F.isDeclaration()) continue;
      ++nFns;
      SmallVector<CallBase *, 8> targets;
      for (Instruction &I : instructions(F))
        if (auto *CB = dyn_cast<CallBase>(&I))
          if (isIndirect(CB)) targets.push_back(CB);

      for (CallBase *CB : targets) {
        IRBuilder<> B(CB);
        Value *t  = CB->getCalledOperand();
        Type  *pt = t->getType();
        Value *ti = B.CreatePtrToInt(t, I64, "jail.t");
        Value *clamped;
        if (mask) {
          Value *orm  = B.CreateLoad(I64, orG,  "jail.or");
          Value *andm = B.CreateLoad(I64, andG, "jail.and");
          clamped = B.CreateAnd(B.CreateOr(ti, orm, "jail.floor"),
                                andm, "jail.ceil");
        } else {
          clamped = B.CreateCall(rt, {ti}, "jail.chk");
        }
        Value *newt = B.CreateIntToPtr(clamped, pt, "jail.p");
        CB->setCalledOperand(newt);
        ++nClamped;
      }
    }
    errs() << "[jail] mode=" << Mode << " module=" << M.getName()
           << " functions=" << nFns << " indirect-calls-clamped=" << nClamped
           << " fakeplt-trampolines=" << nTramp << "\n";
    // module is modified if we clamped a call OR added a trampoline
    return (nClamped || nTramp) ? PreservedAnalyses::none()
                                : PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "JailPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // run late, after optimisation/devirtualisation, so what we clamp
            // is exactly the indirect calls that survive into the final code.
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
                  MPM.addPass(JailPass());
                });
          }};
}
