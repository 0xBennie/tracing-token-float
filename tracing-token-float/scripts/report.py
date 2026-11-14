"""The deliverable: one HTML page, a print version, and a PDF — always the same shape.

Every audit used to end in a differently structured Markdown file, so two reports on two
tokens could not be read side by side, and the parts that matter most (the three exit
numbers, the corrections, the expiry conditions) were the parts most often missing.
This fixes the shape and checks for it.

    python report.py new   --out body.html --name NAME --chain bsc
    python report.py check --body body.html
    python report.py build --body body.html --title "NAME 筹码追踪" --out-dir out/ \\
           --pdf NAME-筹码追踪-20261005.pdf

`build` refuses a body that fails `check`, and refuses one that still carries {{…}}
placeholders. The PDF is printed by headless Chrome/Chromium from the print version
(A4, light theme forced); without a browser it says so and still writes both HTML files.
"""
import argparse, os, re, shutil, subprocess, sys
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent / "assets" / "report"

# The parts a reader relies on. Matched in the body text; each one was missing from
# some earlier report.
REQUIRED = [
    ("stamp: 当前口径", r"<dt>\s*当前口径\s*</dt>"),
    ("stamp: 快照", r"<dt>\s*快照\s*</dt>"),
    ("stamp: 现价", r"<dt>\s*现价\s*</dt>"),
    ("stamp: 数据底座", r"<dt>\s*数据底座\s*</dt>"),
    ("结论 list", r'<ol class="heads">'),
    ("three exit numbers", r"三个数，三个问题"),
    ("① ② ③ columns", r"①.*②.*③"),
    ("sources table", r"每条结论的来源"),
    ("corrections list", r"本轮被推翻的我自己的说法"),
    ("expiry conditions", r"什么时候这份报告作废"),
    ("snapshot block number", r"#\d{1,3}(,\d{3})+"),
    ("UTC timestamp", r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})? UTC"),
]

CHROME = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
          "/Applications/Chromium.app/Contents/MacOS/Chromium",
          "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]


def check(body):
    text = Path(body).read_text()
    missing = [name for name, rx in REQUIRED if not re.search(rx, text, re.S)]
    holes = re.findall(r"\{\{[^}]*\}\}", re.sub(r"<!--.*?-->", "", text, flags=re.S))
    for m in missing:
        print(f"  MISSING  {m}")
    if holes:
        print(f"  UNFILLED {len(holes)} placeholder(s), e.g. {holes[:3]}")
    if not missing and not holes:
        print(f"  check OK — {len(REQUIRED)} required parts present, no placeholders")
    return not missing and not holes


def _chrome():
    for c in CHROME:
        if os.path.isabs(c) and os.path.exists(c):
            return c
        if not os.path.isabs(c) and shutil.which(c):
            return shutil.which(c)
    return None


def build(a):
    if not check(a.body):
        sys.exit("REFUSED: fix the body first — a report missing these parts is the "
                 "inconsistent deliverable this script exists to stop.")
    head = (ASSETS / "head.html").read_text()
    prt = (ASSETS / "print.html").read_text()
    body = re.sub(r"<!--.*?-->\s*", "", Path(a.body).read_text(), flags=re.S)
    pre = ('<!doctype html><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
           f"<title>{a.title}</title>\n")
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(pre + head + "\n" + body)
    (out / "report-print.html").write_text(pre + head + "\n" + prt + "\n" + body)
    print(f"  wrote {out / 'report.html'} and {out / 'report-print.html'}")
    if not a.pdf:
        return
    exe = _chrome()
    if not exe:
        print("  ! no Chrome/Chromium found — PDF not printed. Open report-print.html and "
              "print to PDF (A4) by hand.")
        return
    pdf = out / a.pdf
    r = subprocess.run([exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={pdf}", (out / "report-print.html").resolve().as_uri()],
                       capture_output=True, text=True, timeout=180)
    if not pdf.exists() or pdf.stat().st_size == 0:
        sys.exit(f"PDF not written: {r.stderr[-400:]}")
    pages = len(re.findall(rb"/Type\s*/Page[^s]", pdf.read_bytes()))
    print(f"  wrote {pdf}  ({pdf.stat().st_size:,} bytes, {pages} page(s))")


def main():
    p = argparse.ArgumentParser(description="build the fixed-shape audit report")
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new", help="copy the body skeleton to start a report")
    n.add_argument("--out", required=True)
    n.add_argument("--name", default="{{TOKEN}}", help="token name for the title")
    n.add_argument("--chain", default="{{CHAIN}}")
    c = sub.add_parser("check", help="verify a body has every required part")
    c.add_argument("--body", required=True)
    b = sub.add_parser("build", help="wrap the body, write HTML + print HTML + PDF")
    b.add_argument("--body", required=True)
    b.add_argument("--title", required=True)
    b.add_argument("--out-dir", required=True)
    b.add_argument("--pdf", help="PDF file name inside --out-dir; omit to skip printing")
    a = p.parse_args()
    if a.cmd == "new":
        s = (ASSETS / "skeleton.html").read_text()
        s = s.replace("{{TOKEN}}", a.name).replace("{{CHAIN}}", a.chain.upper())
        if Path(a.out).exists():
            sys.exit(f"{a.out} exists — not overwriting a report body")
        Path(a.out).write_text(s)
        print(f"  wrote {a.out} — fill every {{{{…}}}}, then `report.py check --body {a.out}`")
    elif a.cmd == "check":
        sys.exit(0 if check(a.body) else 1)
    else:
        build(a)


if __name__ == "__main__":
    main()
