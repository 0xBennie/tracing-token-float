"""Shared infrastructure labels — looked up, then re-verified live.

The same exchange wallets, singleton managers and custody vaults turn up in audit after
audit, and each audit used to rediscover them: one re-derived that a "vault" was a
Binance deposit contract, one counted a V4 PoolManager as the biggest buyer of a pump,
one called an exchange's wallet rotation a pre-pump deposit — all three already known
from an earlier case. The file is references/labels-<chain>.json; this script reads it.

    python labels.py --chain bsc show 0xADDR 0xADDR2 ...     # label + live re-check
    python labels.py --chain bsc terminals > terms.json      # for lineage.py trace/closure

A label is a HINT (pitfall #22). `show` re-reads code size and nonce on chain and says
when the live facts disagree with the label's class.
"""
import argparse, json, sys
from pathlib import Path
from rpc import Client, BASE, BSC, ETH

NETS = {"base": BASE, "bsc": BSC, "eth": ETH}
REF = Path(__file__).resolve().parent.parent / "references"
CUSTODIAL_NONCE = 1_000_000


def load(chain):
    p = REF / f"labels-{chain}.json"
    if not p.exists():
        return {}
    return {k.lower(): v for k, v in json.loads(p.read_text()).items() if k.startswith("0x")}


def main():
    p = argparse.ArgumentParser(description="shared infrastructure labels, re-verified live")
    p.add_argument("--chain", required=True, choices=list(NETS))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("show", help="label and live code/nonce for each address")
    s.add_argument("addrs", nargs="+")
    sub.add_parser("terminals", help="print {addr: class} JSON for lineage.py")
    a = p.parse_args()
    L = load(a.chain)
    if a.cmd == "terminals":
        json.dump({k: v["class"].upper() for k, v in L.items()}, sys.stdout, indent=1)
        print()
        return
    c = Client(NETS[a.chain])
    for addr in (x.lower() for x in a.addrs):
        code = c.call("eth_getCode", [addr, "latest"])
        n = int(c.call("eth_getTransactionCount", [addr, "latest"]), 16)
        kind = ("EOA" if code in ("0x", "") else
                "EIP-7702 EOA" if code.startswith("0xef0100") else f"contract {len(code) // 2 - 1}B")
        lab = L.get(addr)
        live = f"{kind}, nonce {n:,}" + (" [custodial-scale]" if n >= CUSTODIAL_NONCE else "")
        if not lab:
            print(f"  {addr}  (no label)  live: {live}")
            continue
        warn = ""
        if lab["class"] == "custodian" and kind == "EOA" and n < 1000 and "cold" not in lab["label"]:
            warn = "  !! label says custodian but nonce is tiny — re-check"
        if lab["class"] == "venue" and kind == "EOA":
            warn = "  !! label says venue but there is no code — wrong chain or wrong address"
        print(f"  {addr}  {lab['label']}  [{lab['class']}, {lab['confidence']}]  live: {live}{warn}")
        print(f"      evidence: {lab['evidence']}")


if __name__ == "__main__":
    main()
