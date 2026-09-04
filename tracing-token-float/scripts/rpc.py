"""Rotating multi-endpoint JSON-RPC with batching.

Public nodes rate-limit, go down, and disagree about block ranges. Rotate on every
call, retry with backoff, and keep batches at or below ~120 items.

    import rpc
    c = rpc.Client(rpc.BASE)
    c.eth_call(token, "0x18160ddd")                       # totalSupply
    c.batch([("eth_call", [{"to": p, "data": d}, "latest"]) for d in datas])
"""
import itertools, time, requests

# Two pools, because they are two different capabilities. Most public nodes serve
# eth_call at `latest` happily and are PRUNED for historical eth_getLogs — and a
# pruned node does not error, it answers `{"result": []}`. Mixing the pools is how
# 126 of 1383 ranges went missing on a BSC replay with no error and no crash.
#
# These lists are a starting point, NOT a guarantee: replay.py qualifies whatever
# pool it is handed against a window known to contain logs and refuses to start if
# nothing answers. Trust the runtime check, not this comment.
BASE = ["https://mainnet.base.org", "https://base-rpc.publicnode.com",
        "https://base.drpc.org", "https://1rpc.io/base", "https://base.meowrpc.com"]
BSC = ["https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com",
       "https://bsc-dataseed1.defibit.io", "https://bsc.drpc.org"]
ETH = ["https://eth.llamarpc.com", "https://ethereum-rpc.publicnode.com", "https://rpc.ankr.com/eth"]

# Endpoints for HISTORICAL eth_getLogs. blxrbdn leads on BSC because it was the only
# free endpoint that answered a full historical replay when every dataseed refused.
# Measured 2026-09-05 by querying windows with a known log count and comparing the
# returned (blockNumber, logIndex) sets across providers. MAX_SPAN is not a preference,
# it is the largest window the endpoint actually serves — exceed it on BSC and blxrbdn
# times out at exactly 30s, deterministically. That is the root cause of the 126/1383
# ranges that once went missing.
LOG_EPS = {
    # blxrbdn is the only free BSC endpoint that serves bulk historical getLogs.
    #   span 500/1000/2000 -> 0% failure;  span 3000/5000 -> 100% failure (30s timeout)
    #   archive floor: block 65,125,025 (2025-10-19). Below that it cannot help.
    # blockrazor caps at 25 blocks and only reaches back ~2 months, but it agreed with
    # blxrbdn exactly on every window tested — keep it as an independent cross-check.
    # NOTE bsc.publicnode.com and bsc-rpc.publicnode.com are ONE backend, not two
    # sources, and both 403 on anything historical.
    "bsc":  ["https://bsc.rpc.blxrbdn.com"],
    # drpc serves 5,000-block spans in ~1.3s and matched every reference set.
    # mainnet.base.org is a true archive but has a response-SIZE cap, so it rejects a
    # dense 200-block window while serving a quiet 5,000-block one — it says so loudly.
    "base": ["https://base.drpc.org", "https://mainnet.base.org"],
    "eth":  ETH,
}

# Largest eth_getLogs window each pool will actually serve. Exceeding it does not
# degrade gracefully; it times out or truncates.
MAX_SPAN = {"bsc": 2000, "base": 2000, "eth": 2000}

# Endpoints that answer eth_blockNumber happily and can never serve logs. Matching these
# evicts the endpoint from rotation instead of burning every retry on it — and, more
# importantly, keeps a node that looks healthy from contributing silent nothing.
DEAD_FOR_LOGS = ("requires a personal token", "is not supported", "method not found",
                 "header not found", "not available on your plan")

MAX_BATCH = 120


class RangeError(Exception):
    """Node refused a log query because the block range or response was too large.

    Distinct from a rate limit, and the distinction is load-bearing: a range error
    means SPLIT THE WINDOW, a rate limit means WAIT AND RETRY THE SAME WINDOW.
    Conflating them bisects a perfectly good window down to single blocks — I did
    exactly that by matching the bare word "limit", and watched a 10-window scan
    turn into 500 one-block windows that each still got throttled.
    """


# Ordered most-specific first. "limit exceeded" alone is ambiguous — Base and BSC
# dataseeds use it for throttling — so it is deliberately NOT a range signal.
RANGE_SIGNS = ("block range", "range is too", "exceed maximum block", "more than",
               "response size", "too large", "result set", "query returned more",
               "logs matched", "query timeout", "range too")
RATE_SIGNS = ("rate limit", "too many request", "429", "capacity", "throttl",
              "quota", "limit exceeded", "over rate")


class Client:
    def __init__(self, endpoints, timeout=30):
        self.endpoints, self.timeout = list(endpoints), timeout
        self._rr = itertools.cycle(self.endpoints)
        self.s = requests.Session()
        self.s.headers.update({"Content-Type": "application/json"})
        self._no_batch = set()   # endpoints whose free tier refuses batched arrays
        self._dead = set()       # endpoints that can never serve this method

    def call(self, method, params, tries=6):
        last, rng = None, 0
        for i in range(tries):
            url = next(self._rr)
            if url in self._dead and len(self._dead) < len(self.endpoints):
                continue
            try:
                resp = self.s.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                              "params": params}, timeout=self.timeout)
                # A 429/503 carrying a JSON body parses fine and looks like a real reply,
                # so the run ends blaming the data instead of the rate limit.
                resp.raise_for_status()
                j = resp.json()
                if "error" in j:
                    msg = str(j["error"]).lower()
                    last = f"{url}: {j['error']}"
                    if any(k in msg for k in DEAD_FOR_LOGS):
                        self._dead.add(url)      # never ask this one again
                        continue
                    if any(k in msg for k in RANGE_SIGNS) and \
                       not any(k in msg for k in RATE_SIGNS):
                        # One node's range cap is not every node's. Rotate first and only
                        # declare the window too large if EVERY endpoint says so —
                        # otherwise a single stingy node makes the caller split a window
                        # that the next endpoint would have served whole.
                        rng += 1
                        continue
                    if any(k in msg for k in RATE_SIGNS):
                        time.sleep(1.5 * (i + 1))     # back off, do NOT split the window
                    continue
                if "result" not in j:
                    last = f"{url}: reply had neither result nor error"
                    continue
                if j["result"] is None:
                    last = f"{url}: result=null"      # never hand None to a caller
                    continue
                return j["result"]
            except RangeError:
                raise
            except Exception as e:
                last = f"{url}: {e}"
            time.sleep(0.35 * (i + 1))
        if rng and rng >= min(tries, len(self.endpoints)):
            raise RangeError(f"every endpoint refused the range :: {last}")
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
