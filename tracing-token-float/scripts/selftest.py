#!/usr/bin/env python3
"""Check the skill against itself. No network, no chain, runs in a second.

    python selftest.py            # exit 0 = consistent, 1 = something below is wrong

Every check here exists because the corresponding mistake actually shipped:

  - A runbook command carried `--quote auto`, and `auto` is not an address. Argparse
    accepted it, it was zero-padded into calldata, and the empty reply read as "that
    pool does not exist". Documented commands are now parsed and their flags and
    address-shaped values checked.
  - Event topics and role hashes were typed from memory. One Mint topic's first 22 hex
    characters were right and the rest was not; eth_getLogs answered `[]` without error
    and a deliverable said the pool's book had been static for a million blocks. Every
    constant that can be derived is re-derived here and compared.
  - README said 27 pitfalls after there were 30, and listed a scripts/ directory that
    had grown three files. Counts are recomputed.
  - pitfalls.md is referenced by number from the code and the prose. A renumber breaks
    every one of those references silently, so the numbering is checked for gaps.
  - The selector scan read PUSH4 only, so a function whose selector starts 0x00 (solc
    pushes it with PUSH3) was invisible — a full-balance withdraw read as absent. The
    dispatcher shapes are checked on synthetic bytecode, both ways.
  - An Infura range cap ("range 19999 exceeds limit of 10000") matched no range sign,
    and a bare "429" matched inside a block number. Error classes are checked on a
    table of real messages, and the redaction of API keys in error text with them.

What it deliberately does NOT do: touch the network. A self-test that needs an archive
node is a self-test nobody runs.
"""
import ast, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
FAIL = []
NOTE = []


def fail(check, msg):
    FAIL.append(f"[{check}] {msg}")


def note(msg):
    NOTE.append(msg)


# ---------------------------------------------------------------- constants
def check_constants():
    """Anything derivable must equal its derivation. Values, not just presence."""
    sys.path.insert(0, str(SCRIPTS))
    try:
        import topics as TP
    except Exception as e:
        return fail("constants", f"topics.py will not import: {e}")

    # topic0 is keccak of the signature — recompute from the signature strings the
    # module itself publishes, so a corrupted table cannot agree with itself.
    for k, sig in TP.SIG.items():
        if TP.T[k] != TP.topic0(sig):
            fail("constants", f"topics.T[{k}] != keccak({sig})")

    # The two Swap variants must differ, or the fork distinction this skill turns on
    # has quietly collapsed.
    if TP.T["v3.Swap"] == TP.T["pancake.Swap"]:
        fail("constants", "Uniswap and PancakeSwap Swap topics are equal — "
                          "the fork distinction is gone")

    try:
        import control
        for name, sig in (("PROPOSER", "PROPOSER_ROLE"), ("EXECUTOR", "EXECUTOR_ROLE"),
                          ("CANCELLER", "CANCELLER_ROLE"),
                          ("ADMIN", "TIMELOCK_ADMIN_ROLE")):
            got = getattr(control, "ROLES", {}).get(name)
            if got and got != TP.topic0(sig):
                fail("constants", f"control.ROLES[{name}] != keccak({sig})")
    except Exception as e:
        note(f"control.py roles not checked ({e})")

    # EIP-1967 slots are keccak(label) - 1, and all three are in privileges.py.
    from Crypto.Hash import keccak as _k
    def slot(label):
        h = _k.new(digest_bits=256); h.update(label.encode())
        return "0x%064x" % (int.from_bytes(h.digest(), "big") - 1)
    try:
        import privileges as PV
        for attr, label in (("SLOT_IMPL", "eip1967.proxy.implementation"),
                            ("SLOT_ADMIN", "eip1967.proxy.admin"),
                            ("SLOT_BEACON", "eip1967.proxy.beacon")):
            if getattr(PV, attr, None) != slot(label):
                fail("constants", f"privileges.{attr} != keccak('{label}') - 1")
    except Exception as e:
        note(f"privileges.py slots not checked ({e})")

    # The DANGEROUS table is typed, and its comment says every entry was computed. Make
    # that true on every run: a wrong selector reads as "this contract has no mint".
    try:
        import privileges as PV
        for sel, (sig, _) in PV.DANGEROUS.items():
            if TP.selector(sig) != sel:
                fail("constants", f"privileges.DANGEROUS[{sel}] is not selector({sig}) "
                                  f"= {TP.selector(sig)}")
    except Exception as e:
        note(f"privileges.DANGEROUS not checked ({e})")


# ---------------------------------------------------------------- behaviour
def check_dispatch():
    """selectors() must find short-pushed selectors in dispatcher shape, and nothing else."""
    try:
        import privileges as PV
    except Exception as e:
        return fail("dispatch", f"privileges.py will not import: {e}")
    # CALLDATALOAD PUSH1 e0 SHR, then: DUP1 PUSH3 f714ce EQ PUSH2 15ed JUMPI (the 0x00
    # selector), DUP1 PUSH4 0dfe1681 EQ PUSH2 159d JUMPI, PUSH4 e2bbb158 EQ PUSH2 00fc
    # JUMPI (last entry, no DUP1), PUSH0 DUP1 REVERT.
    table = ("3560e01c" "8062f714ce146115ed57" "80630dfe1681146115" "9d57"
             "63e2bbb1581461" "00fc57" "5f80fd")
    got = PV.selectors("0x" + table)
    for want in ("0x00f714ce", "0x0dfe1681", "0xe2bbb158"):
        if want not in got:
            fail("dispatch", f"selectors() missed {want} in a synthetic dispatch table")
    for jump in ("0x000015ed", "0x0000159d", "0x000000fc"):
        if jump in got:
            fail("dispatch", f"selectors() reported the PUSH2 jump target {jump} as a selector")
    # A short LAST entry (no DUP1) after a PUSH4 entry is still the table.
    tail = "3560e01c" "80630dfe16811461159d57" "62abcdef146100fc57"
    if "0x00abcdef" not in PV.selectors("0x" + tail):
        fail("dispatch", "selectors() missed a PUSH3 selector in the last dispatch slot")
    # Ordinary `if (x == 0)` / `if (x == 2)` has the same five-opcode shape. Unanchored,
    # it is not a dispatch table.
    code = "600081146101235780600214610456575b"
    if PV.selectors("0x" + code):
        fail("dispatch", f"selectors() read ordinary comparisons as selectors: "
                         f"{sorted(PV.selectors('0x' + code))}")
    if "0xdeadbeef" not in PV.selectors("0x63deadbeef50"):
        fail("dispatch", "selectors() stopped collecting every PUSH4")


def check_error_classes():
    """rpc.classify on real node messages — range, rate and revert must not collide."""
    try:
        import rpc
    except Exception as e:
        return fail("errors", f"rpc.py will not import: {e}")
    table = [
        ("range 19999 exceeds limit of 10000", "range"),                 # infura
        ("range 14290 exceeds limit of 10000", "range"),                 # contains 429
        ({"code": -32005, "message": "query returned more than 10000 results"}, "range"),
        ("exceed maximum block range: 50000", "range"),                  # nodereal
        ("logs count exceeds the limit 50000", "range"),                 # nodereal
        ("You have reached the maximum API usage limit of public key", "rate"),
        ("limit exceeded", "rate"),                                      # dataseeds
        ("daily request count exceeded, request rate limited", "rate"),
        ("Your app has exceeded its compute units per second capacity", "rate"),
        ("429 Too Many Requests", "rate"),
        ("request exceeds limit of 25 requests per second", "rate"),
        ("execution reverted: transfer amount exceeds limit of wallet", "revert"),
        ("method not found", "dead"),
    ]
    for msg, want in table:
        got = rpc.classify(msg)
        if got != want:
            fail("errors", f"classify({str(msg)[:50]!r}) = {got}, want {want}")
    key = "0123456789abcdef0123456789abcdef"
    for url in (f"https://bsc-mainnet.infura.io/v3/{key}",
                f"https://bsc-mainnet.nodereal.io/v1/{key}",
                f"https://rpc.example.org/?apikey={key}&x=1"):
        if key in rpc.redact(f"rpc failed :: {url}: 429 for url: {url}"):
            fail("errors", f"redact() left an API key in {url.split('/')[2]} error text")
    if rpc.redact("https://bsc-dataseed.bnbchain.org") != "https://bsc-dataseed.bnbchain.org":
        fail("errors", "redact() mangled a URL that carries no key")


# ---------------------------------------------------------------- runbook
def _argparse_flags(path):
    """Flags a script declares, read from its AST — no import, no side effects."""
    flags, sub = set(), False
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "add_argument":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and str(arg.value).startswith("-"):
                    flags.add(str(arg.value))
        if isinstance(f, ast.Attribute) and f.attr in ("add_subparsers", "add_parser"):
            sub = True
    return flags, sub


def check_runbook():
    """Every documented command must name a script that exists and flags it declares."""
    skill = (ROOT / "SKILL.md").read_text()
    cmds = re.findall(r"^python (?:scripts/)?(\w+\.py)([^\n#]*)", skill, re.M)
    if not cmds:
        return fail("runbook", "no `python x.py` commands found in SKILL.md at all")
    for script, argstr in cmds:
        path = SCRIPTS / script
        if not path.exists():
            fail("runbook", f"SKILL.md runs {script}, which does not exist")
            continue
        declared, has_sub = _argparse_flags(path)
        used = set(re.findall(r"--[a-z0-9-]+", argstr))
        missing = used - declared
        if missing and not has_sub:
            fail("runbook", f"{script} has no flag(s) {sorted(missing)}")
        # A value that LOOKS like an address must be one, or a placeholder. `--quote
        # auto` shipped, and argparse cannot tell you that.
        for flag, val in re.findall(r"(--[a-z0-9-]+)\s+([^\s\\]+)", argstr):
            if flag in ("--token", "--pool", "--quote", "--nfpm", "--issuer"):
                ok = (re.fullmatch(r"0x[0-9a-fA-F]{40}", val)        # a real address
                      or re.fullmatch(r"0x[A-Z][A-Z0-9_]*\.{0,3}", val)  # 0xTOKEN, 0xABC...
                      or re.fullmatch(r"<[a-z-]+>", val))             # <lo>, <deploy>
                if not ok:
                    fail("runbook", f"{script} {flag} {val!r} is neither an address nor "
                                    f"an obvious placeholder — this is how `--quote "
                                    f"auto` got documented")


# ---------------------------------------------------------------- references
def check_pitfalls():
    """Numbering must be dense and ascending: everything cites these by number."""
    text = (ROOT / "references" / "pitfalls.md").read_text()
    nums = [int(n) for n in re.findall(r"^## (\d+)\.", text, re.M)]
    if not nums:
        return fail("pitfalls", "no numbered entries found")
    if nums != sorted(nums):
        fail("pitfalls", f"entries are not in ascending order: {nums}")
    expected = list(range(1, len(nums) + 1))
    if nums != expected:
        gaps = sorted(set(expected) - set(nums))
        dupes = sorted({n for n in nums if nums.count(n) > 1})
        fail("pitfalls", f"numbering is not dense 1..{len(nums)}"
                         + (f"; missing {gaps}" if gaps else "")
                         + (f"; duplicated {dupes}" if dupes else ""))

    # Every #N referenced from code or prose must exist.
    cited = set()
    for p in list(SCRIPTS.glob("*.py")) + [ROOT / "SKILL.md",
                                           ROOT / "references" / "v3-depth.md"]:
        cited |= {int(n) for n in re.findall(r"pitfalls? #(\d+)", p.read_text())}
    dangling = sorted(cited - set(nums))
    if dangling:
        fail("pitfalls", f"referenced but absent: {dangling}")
    return len(nums)


def check_readme(n_pitfalls):
    """The README describes the tree; the tree changes more often than the README."""
    rp = ROOT.parent / "README.md"
    if not rp.exists():
        return note("no README.md beside the skill — skipped")
    text = rp.read_text()
    m = re.search(r"pitfalls\.md\s+(\d+) traps", text)
    if not m:
        note("README does not state a pitfall count")
    elif int(m.group(1)) != n_pitfalls:
        fail("readme", f"README says {m.group(1)} pitfalls, there are {n_pitfalls}")
    listed = set(re.findall(r"^\s{4}(\w+\.py)", text, re.M))
    actual = {p.name for p in SCRIPTS.glob("*.py")} - {"__init__.py"}
    if actual - listed:
        fail("readme", f"scripts not listed in README: {sorted(actual - listed)}")
    if listed - actual:
        fail("readme", f"README lists scripts that do not exist: {sorted(listed - actual)}")


# ---------------------------------------------------------------- hygiene
def check_retracted_wording():
    """The label this skill retracted must not survive as live guidance anywhere.

    "third-party reachable quote" was the name given to an inventory statistic. It is
    still quoted inside the correction that retires it, so a bare grep is useless —
    this looks for it in argparse help and in docstrings, where it would be read as
    instruction rather than as history.
    """
    bad = re.compile(r"third[- ]party (can )?reach|number that matters", re.I)
    for p in SCRIPTS.glob("*.py"):
        tree = ast.parse(p.read_text())
        doc = ast.get_docstring(tree) or ""
        if bad.search(doc) and "pitfall" not in doc.lower():
            fail("retracted", f"{p.name} docstring still teaches the retired label")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
               and node.func.attr == "add_argument":
                for kw in node.keywords:
                    if kw.arg == "help" and isinstance(kw.value, ast.Constant):
                        h = str(kw.value.value)
                        if bad.search(h) and "#21" not in h:
                            fail("retracted", f"{p.name} --help text still teaches the "
                                              f"retired label: {h[:70]}")


def check_syntax():
    for p in sorted(SCRIPTS.glob("*.py")):
        try:
            ast.parse(p.read_text())
        except SyntaxError as e:
            fail("syntax", f"{p.name}: {e}")


def main():
    check_syntax()
    check_constants()
    check_dispatch()
    check_error_classes()
    check_runbook()
    n = check_pitfalls()
    check_readme(n or 0)
    check_retracted_wording()

    for m in NOTE:
        print(f"  note: {m}")
    if FAIL:
        print(f"\n  {len(FAIL)} PROBLEM(S):")
        for f in FAIL:
            print(f"    {f}")
        sys.exit(1)
    print(f"  selftest OK — {n} pitfalls, "
          f"{len(list(SCRIPTS.glob('*.py')))} scripts, constants re-derived, "
          f"runbook commands resolve")


if __name__ == "__main__":
    main()
