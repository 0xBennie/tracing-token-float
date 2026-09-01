"""Rotating multi-endpoint JSON-RPC with batching.

Public nodes rate-limit, go down, and disagree about block ranges. Rotate on every
call, retry with backoff, and keep batches at or below ~120 items.

    import rpc
    c = rpc.Client(rpc.BASE)
    c.eth_call(token, "0x18160ddd")                       # totalSupply
    c.batch([("eth_call", [{"to": p, "data": d}, "latest"]) for d in datas])
"""
import itertools, time, requests

BASE = ["https://mainnet.base.org", "https://base-rpc.publicnode.com",
        "https://base.drpc.org", "https://1rpc.io/base", "https://base.meowrpc.com"]
BSC = ["https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com",
       "https://bsc-dataseed1.defibit.io", "https://bsc.drpc.org"]
ETH = ["https://eth.llamarpc.com", "https://ethereum-rpc.publicnode.com", "https://rpc.ankr.com/eth"]

MAX_BATCH = 120


class RangeError(Exception):
    """Node refused a log query because the block range or response was too large."""


class Client:
    def __init__(self, endpoints, timeout=30):
        self.endpoints, self.timeout = list(endpoints), timeout
        self._rr = itertools.cycle(self.endpoints)
        self.s = requests.Session()
        self.s.headers.update({"Content-Type": "application/json"})
        self._no_batch = set()   # endpoints whose free tier refuses batched arrays

    def call(self, method, params, tries=6):
        last = None
        for i in range(tries):
            url = next(self._rr)
            try:
                j = self.s.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                           "params": params}, timeout=self.timeout).json()
                if "error" in j:
                    msg = str(j["error"]).lower()
                    last = f"{url}: {j['error']}"
                    if any(k in msg for k in ("range", "more than", "response size", "too large")):
                        raise RangeError(msg)
                    continue
                return j["result"]
            except RangeError:
                raise
            except Exception as e:
                last = f"{url}: {e}"
            time.sleep(0.35 * (i + 1))
        raise RuntimeError(f"rpc failed [{method}] :: {last}")

    def batch(self, reqs, tries=6):
        """reqs: [(method, params), ...] -> [result, ...] in the same order."""
        if len(reqs) > MAX_BATCH:
            out = []
            for i in range(0, len(reqs), MAX_BATCH):
                out += self.batch(reqs[i:i + MAX_BATCH], tries)
            return out
        payload = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p}
                   for i, (m, p) in enumerate(reqs)]
        last = None
        for k in range(tries * 2):
            url = next(self._rr)
            if url in self._no_batch:
                continue
            try:
                j = self.s.post(url, json=payload, timeout=self.timeout * 2).json()
                if isinstance(j, dict):
                    last = f"{url}: {j.get('error')}"
                    if "batch" in str(j.get("error", "")).lower():
                        self._no_batch.add(url)   # e.g. drpc free tier caps batches at 3
                    continue
                out = [None] * len(reqs)
                for item in j:
                    if "error" in item:
                        raise ValueError(item["error"])
                    out[item["id"]] = item["result"]
                if all(o is not None for o in out):
                    return out
            except Exception as e:
                last = f"{url}: {e}"
            time.sleep(0.4 * (k + 1))
        raise RuntimeError(f"batch failed :: {last}")

    def eth_call(self, to, data, block="latest"):
        return self.call("eth_call", [{"to": to, "data": data}, block])

    def erc20_balance(self, token, holder, dec=18, block="latest"):
        return int(self.eth_call(token, "0x70a08231" + holder[2:].rjust(64, "0"), block), 16) / 10 ** dec

    def block_number(self):
        return int(self.call("eth_blockNumber", []), 16)


def s256(v):
    """Two's-complement decode of a full 256-bit ABI word. Use for every signed return."""
    return v - (1 << 256) if v >= (1 << 255) else v
