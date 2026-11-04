# Linux command line for this demo — A to Z (never used it before)

Everything here is what you actually need to present confidently: move around,
open/show files, compare code and assembly, run things, and split the screen.
You do NOT need to learn all of Linux — just these ~15 commands.

---

## 0. Mental model (read once)

- Two copies of the project exist: one on your **Mac** (`.../platypus-arm64/`,
  open these in any editor for slides) and one **inside the VM** (`~/e0256/`,
  this is where things compile and run). They have the same files.
- A command line is just: **type a command, press Enter, read the output.**
- You will not break anything by *looking*. `ls`, `cat`, `less`, `grep` only read.

## 1. Get into the VM
```bash
limactl start e0256      # wake the VM (safe to run even if already on)
limactl shell e0256      # enter it — your prompt changes
cd ~/e0256               # go to the project
```
Leave with `exit`. Clear a messy screen with `clear` (or Cmd+K on the Mac).

## 2. Three reflexes that make you look fluent
- **Tab key = autocomplete.** Type `cat tests/hij` then press **Tab** → it fills
  in `hijack_poc.c`. Use it constantly; you never type full names.
- **Up arrow = last command.** Re-run or edit the previous command instead of
  retyping.
- **Ctrl+C = stop.** If anything hangs or scrolls forever, press Ctrl+C.

## 3. "Where am I / what's here?" — navigating
```bash
pwd                 # print working directory (where am I)
ls                  # list files here
ls -la              # list ALL files with details (sizes, dates)
cd pass             # go into the pass/ folder
cd ..               # go up one level
tree -L 2           # a pretty tree of folders (depth 2)
```

## 4. "Open this file and show me" — the #1 thing sir will ask
Pick ONE of these:
```bash
batcat tests/hijack_poc.c      # BEST for showing: colored, line numbers, paged
cat tests/hijack_poc.c         # dump the whole file to the screen
less tests/hijack_poc.c        # scrollable viewer: arrows/PageDn, /word to search, q to quit
```
- `batcat` is the nicest for a demo (syntax colors + line numbers). Inside its
  pager: arrows to scroll, `q` to quit.
- To show **just one function / some lines**:
  ```bash
  sed -n '30,55p' tests/hijack_poc.c      # show lines 30–55
  grep -n "fp" tests/hijack_poc.c         # show every line containing fp, with line numbers
  ```
- Tip: make `bat` short — run `alias bat=batcat` once per session, then type `bat`.

## 5. "Show me the assembly of this" — code → machine instructions
Two ways, both real:
```bash
# (a) compile source straight to assembly text:
JAIL=mask bin/a64cc -S -O2 tests/toy_indirect.c -o /tmp/toy.s
batcat /tmp/toy.s

# (b) disassemble a finished binary (what actually runs):
objdump -d demos/out/toy_jail | less
```
Pre-made assembly for the talk is already in `demos/asm/` (`toy_base.s`,
`toy_jail.s`, `poc_base.s`, `poc_jail.s`).

**Compare two versions side by side** (the key teaching move):
```bash
diff demos/asm/toy_base.s demos/asm/toy_jail.s       # lines with > are what our pass added
sdiff -w 180 demos/asm/toy_base.s demos/asm/toy_jail.s | less   # true side-by-side, q to quit
```

## 6. "Run it and show the result"
```bash
demos/out/poc_unhard hijack     # the exploit, unhardened → prints your id (shell ran)
demos/out/poc_hard   hijack     # same exploit, hardened → Segmentation fault (blocked)
echo "exit code was: $?"        # $? = the exit code of the last command
```

## 7. "What other files did you use?" — show the whole project
```bash
tree -L 2 --dirsfirst                  # the structure
batcat README.md                       # the overview
ls tools bench pass runtime tests      # the source by area
```
Say: "source is organised by role — `pass/` the compiler pass, `runtime/` the
start-up code, `tools/` the measurement scripts, `tests/` the demos, `bench/` the
benchmarks." It's all in `README.md`.

## 8. Searching (when sir asks "where do you do X?")
```bash
grep -n "dl_iterate_phdr" runtime/jail_rt.c     # find a word in one file (with line #s)
grep -rn "installFakePlt" pass/                 # find it anywhere under pass/
```

---

## 9. Split screen — showing code and running it at the same time

**Option A — two Mac Terminal tabs (easiest, do this).**
In the Mac Terminal: **Cmd+T** opens a new tab. In each tab run
`limactl shell e0256` then `cd ~/e0256`. Now one tab shows the file
(`batcat tests/hijack_poc.c`), the other runs it (`demos/out/poc_unhard hijack`).
Switch tabs with **Cmd+Shift+[** / **Cmd+Shift+]**.

**Option B — tmux, split inside ONE window (looks expert).**
```bash
tmux                # start it (you're now in a tmux session)
```
- Split **left/right**: press **Ctrl+b** then **%**
- Split **top/bottom**: press **Ctrl+b** then **"**
- Move between panes: **Ctrl+b** then an **arrow key**
- Each pane is a normal shell — `cd ~/e0256` in each.
- Close a pane: type `exit` in it. Leave tmux entirely: `exit` all panes.
Practice this once before the talk; the only trick is "Ctrl+b first, then the key".

**Option C — hybrid (least typing).** Open the file on your **Mac** in an editor
(it's the same file at `.../platypus-arm64/...`), keep the VM terminal for running.
Code on the big screen, results in the terminal.

---

## 10. A 60-second dry run to build muscle memory
```bash
limactl shell e0256
cd ~/e0256
tree -L 1
batcat tests/hijack_poc.c          # press q to quit
diff demos/asm/toy_base.s demos/asm/toy_jail.s
demos/out/poc_unhard hijack
demos/out/poc_hard   hijack
exit
```
Do this three times and you'll look like you've used Linux for years.

## 11. If you get stuck
- Screen full of junk → `clear`.
- "command not found" for `limactl` → use `/opt/homebrew/bin/limactl`.
- A viewer won't close → press **q** (in `less`/`batcat`) or **Ctrl+C**.
- Forgot a filename → type the folder + `/` then press **Tab** to list options.
