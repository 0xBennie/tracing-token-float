"""Rotating multi-endpoint JSON-RPC with batching.

Public nodes rate-limit, go down, and disagree about block ranges. Rotate on every
call, retry with backoff, and keep batches at or below ~120 items.

    import rpc
    c = rpc.Client(rpc.BASE)
    c.eth_call(token, "0x18160ddd")                       # totalSupply
    c.batch([("eth_call", [{"to": p, "data": d}, "latest"]) for d in datas])
"""
import atexit, collections, itertools, re, sys, time, requests

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

# Endpoints for HISTORICAL eth_getLogs, keyed by chain — every entry qualified by
# querying windows with a known log count and comparing the returned
# (blockNumber, logIndex) sets across providers. Qualify, don't assume: a pruned node
# answers a range it cannot serve with `{"result": []}`, byte-identical to a genuinely
# quiet range.
LOG_EPS = {
    # nodereal's public-key endpoint is a TRUE archive for eth_getLogs across all of
    # BSC history. Qualified 2026-09-08 against WBNB Transfer logs in 10-block windows
    # at blocks 45M/50M/55M/56M/58M/59M/60M/62M/66M/80M/100M/120M — all non-empty —
    # and it matched blxrbdn log-for-log on 66,000,000-66,001,999 (476/476).
    #   two separate caps, and BOTH say so explicitly instead of truncating:
    #     block range   50,000  -> "exceed maximum block range: 50000"
    #     result count  50,000  -> "logs count exceeds the limit 50000"
    #   throughput: a 50,000-block span answers in ~3.4s, but the ceiling is
    #   CONCURRENCY, not span — 8 workers 429'd every window, 2 workers ran 61.1M
    #   blocks clean. Sustained serial rate on dense history is ~0.07 windows/s, so
    #   a 10M-transfer replay is an hours-long job however you slice it.
    #
    # This REPLACES an earlier claim in this file that blxrbdn was the only free BSC
    # endpoint serving bulk historical getLogs. It was not, and worse, blxrbdn has an
    # archive floor around block 66M (2025-10-19) — it cannot serve a token deployed
    # before that date at all, which is most of them. It stays in XCHECK_EPS below.
    #
    # NOTE bsc.publicnode.com and bsc-rpc.publicnode.com are ONE backend, not two
    # sources, and both 403 on anything historical. blastapi and zan.top are true
    # archives for eth_call/eth_getCode (use them for a deploy-block bisect) but their
    # free tier refuses eth_getLogs outright with HTTP 429 at any span.
    "bsc":  ["https://bsc-mainnet.nodereal.io/v1/64a9df0874fb4a93b9d0a3849de012d3"],
    # drpc serves 5,000-block spans in ~1.3s and matched every reference set.
    # mainnet.base.org is a true archive but has a response-SIZE cap, so it rejects a
    # dense 200-block window while serving a quiet 5,000-block one — it says so loudly.
    "base": ["https://base.drpc.org", "https://mainnet.base.org"],
    "eth":  ETH,
}

# A SECOND, independent provider per chain, for the one job that cannot be done with a
# single endpoint: confirming that an empty or suspiciously round result is the chain's
# answer and not the node's. Deliberately NOT in LOG_EPS — that dict is indexed by chain
# name (LOG_EPS[a.chain]) and a non-chain key in it breaks the first caller to iterate it.
# blockrazor caps at 25 blocks and reaches back only ~2 months, but it agreed with
# blxrbdn on every window ever tested, which is exactly what a cross-check needs.
XCHECK_EPS = {"bsc": ["https://bsc.rpc.blxrbdn.com", "https://bsc.blockrazor.xyz"]}

# Largest eth_getLogs window each pool will actually serve. Exceeding it does not
# degrade gracefully; it times out or truncates.
# bsc 20,000 and not nodereal's 50,000 block ceiling: on dense history a 50,000-block
# window trips the 50,000-RESULT cap instead, and each trip costs a bisection. 20,000
# stayed under both caps across a 3,058-window replay.
MAX_SPAN = {"bsc": 20000, "base": 2000, "eth": 2000}

# Endpoints that answer eth_blockNumber happily and can never serve logs. Matching these
# evicts the endpoint from rotation instead of burning every retry on it — and, more
# importantly, keeps a node that looks healthy from contributing silent nothing.
DEAD_FOR_LOGS = ("requires a personal token", "is not supported", "method not found",
                 "header not found", "not available on your plan")

MAX_BATCH = 100


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
               "logs matched", "query timeout", "range too",
               # nodereal: "logs count exceeds the limit 50000" — a RESULT cap, not a
               # block-range cap, and it matched nothing in this tuple before. Note it is
               # "exceeds the limit", NOT nodereal's throttle text "limit exceeded" below.
               "exceeds the limit", "count exceeds",
               # Infura: "query returned more than 10000 results" is covered above, but
               # its block-range cap reads "range 19999 exceeds limit of 10000" — no
               # "the", no "block range" — and matched nothing, so an over-wide window
               # was retried as-is until it failed instead of being split.
               "exceeds limit of")
RATE_SIGNS = ("rate limit", "too many request", "429", "capacity", "throttl",
              "quota", "limit exceeded", "over rate",
              # nodereal throttles with "You have reached the maximum API usage limit of
              # public key ..." — contains the word "limit" but is a BACKOFF, not a split.
              "usage limit", "reached the maximum api",
              # A throttle phrased as a count per unit time ("exceeds limit of 25 requests
              # per second") would otherwise read as the Infura range cap above.
              "per second", "per minute", "requests per")


def _has(msg, signs):
    """Substring match — except that an all-digit sign must stand alone. A bare "429"
    matched inside "range 14290 exceeds limit of 10000" and vetoed the range signal,
    so a window that needed splitting was backed off and retried at the same size."""
    return any(re.search(rf"(?<!\d){k}(?!\d)", msg) if k.isdigit() else k in msg
               for k in signs)


def classify(msg):
    """What an error message asks of the caller: "dead" (never ask this endpoint this
    again), "range" (split the window), "rate" (wait, retry the SAME window), "revert"
    (the chain answered — stop), or None (unknown: rotate and retry).

    Order is the contract. A revert is checked BEFORE the range signs: revert reasons
    are free text, and "execution reverted: amount exceeds limit of wallet" or "...
    more than balance" would otherwise be split as if the node had refused a range.
    And rate VETOES range: a message carrying both is a throttle, because splitting a
    throttled window multiplies the throttling (pitfall #24)."""
    m = str(msg).lower()
    if _has(m, DEAD_FOR_LOGS):
        return "dead"
    if _has(m, PRUNED_SIGNS):
        return "pruned"
    if _has(m, REVERT_SIGNS):
        return "revert"
    rate = _has(m, RATE_SIGNS)
    if _has(m, RANGE_SIGNS) and not rate:
        return "range"
    if rate:
        return "rate"
    return None


# An API key in a URL path is a credential. Endpoint URLs end up in exception text,
# exception text ends up in logs, and one replay wrote a paid key into every
# `replay*.log` it produced. /v1/<key> (nodereal), /v2/<key> (alchemy), /v3/<key>
# (infura), and the usual query-string spellings.
_KEY_PATH = re.compile(r"(/v\d+/)([A-Za-z0-9_-]{16,})")
_KEY_QUERY = re.compile(r"((?:api[_-]?key|apikey|key|token)=)[^&\s'\"]+", re.I)


def redact(text):
    """`text` with API-key path segments and key query parameters masked."""
    return _KEY_QUERY.sub(r"\1***", _KEY_PATH.sub(r"\1***", str(text)))



# An execution revert is the CHAIN answering. It is not a refusal, it will say the same
# thing on every endpoint, and rotating through them to collect the same revert wastes
# the rate limit that the next real question needs. Pitfall #26 draws this line and the
# first version of this census ignored it: a contract with no owner() reported "1 request
# never answered", which is both wrong and the exact confusion the census exists to stop.
REVERT_SIGNS = ("execution reverted", "revert", "invalid opcode", "out of gas",
                "stack underflow", "invalid jump")


# A pruned node asked for state it no longer keeps. Public BSC nodes keep roughly the
# last 128 blocks; a balanceOf at a block fifty minutes old already comes back as
# "missing trie node". Every pruned endpoint gives the same answer, so this is neither a
# refusal a retry fixes nor a revert — it means "ask an archive node". Left
# unclassified it was rotated through every pruned endpoint and booked as a refusal,
# and poolflow's balance identity (the gate that catches a short log read) never ran.
PRUNED_SIGNS = ("missing trie node", "archive request", "historical state",
                "state is not available", "state histories")


class PrunedStateError(RuntimeError):
    """This endpoint does not keep the state asked for. Use an archive pool."""


class RevertError(RuntimeError):
    """The chain answered, and the answer was a revert. Data, not a refusal."""

    def __init__(self, msg, data=None):
        super().__init__(msg)
        self.data = data


class Census:
    """asked / answered / refused, for the whole process, printed whether you remember
    to or not.

    Pitfall #26 says to count refusals and print the count. It said so for a long time
    while `Client` carried no counter at all, so the discipline lived in whoever
    remembered it — and a run that answered 13 of 20 windows printed the same-looking
    report as one that answered 20 of 20. Counting here, at the transport, is the only
    place it cannot be forgotten.

    Counted once per LOGICAL request, never per retry: the question is how many of the
    questions the analysis asked came back answered, not how many round trips it cost.
    `empty` counts answers that WERE data but came back `[]` — the shape a pruned node
    fakes — so they sit beside the refusals instead of inside them.
    """

    def __init__(self):
        self.asked = collections.Counter()
        self.answered = collections.Counter()
        self.refused = collections.Counter()
        self.empty = collections.Counter()
        self.reverted = collections.Counter()

    def totals(self):
        return (sum(self.asked.values()), sum(self.answered.values()),
                sum(self.refused.values()), sum(self.empty.values()))

    def reverts(self):
        return sum(self.reverted.values())

    def line(self):
        a, k, r, e = self.totals()
        return (f"RPC CENSUS  asked {a:,}  answered {k:,}  refused {r:,} "
                f"({(r / a * 100 if a else 0):.1f}%)  empty-but-answered {e:,}  "
                f"reverted-by-chain {self.reverts():,}")


CENSUS = Census()


def _print_census():
    a, k, r, e = CENSUS.totals()
    if not a:
        return
    print("\n  " + CENSUS.line(), file=sys.stderr)
    for m in sorted(CENSUS.asked):
        print(f"    {m:<26} asked {CENSUS.asked[m]:>7,}  answered {CENSUS.answered[m]:>7,}"
              f"  refused {CENSUS.refused[m]:>7,}  empty {CENSUS.empty[m]:>7,}",
              file=sys.stderr)
    if CENSUS.reverts():
        print(f"    ({CENSUS.reverts():,} call(s) reverted — that is the CHAIN answering, "
              f"counted as answered, not as a refusal.)", file=sys.stderr)
    if r:
        print(f"    !! {r:,} request(s) were never answered. Every 'none found', 'no "
              f"events', 'no pool', 'no position manager' above is a FLOOR, not a fact "
              f"(pitfall #26).", file=sys.stderr)


# Registered at import, so no script can forget to print it and no run can look clean
# merely because its author did not think to ask.
atexit.register(_print_census)


def census_gate(max_refused_pct=0.0, what="conclusion"):
    """Exit non-zero when too much of the run went unanswered. Call before publishing."""
    a, _, r, _ = CENSUS.totals()
    if a and (r / a * 100) > max_refused_pct:
        sys.exit(f"REFUSED: {r:,}/{a:,} requests unanswered ({r / a * 100:.1f}%). A "
                 f"{what} drawn over that is absence of evidence reported as evidence "
                 f"of absence (pitfall #26). Re-run, or print the coverage next to "
                 f"the number.")


class Client:
    def __init__(self, endpoints, timeout=30):
        self.endpoints, self.timeout = list(endpoints), timeout
        self._rr = itertools.cycle(self.endpoints)
        self.s = requests.Session()
        self.s.headers.update({"Content-Type": "application/json"})
        self._no_batch = set()   # endpoints whose free tier refuses batched arrays
        self._dead = set()       # endpoints that can never serve this method

    def call(self, method, params, tries=6):
        CENSUS.asked[method] += 1
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
                # An HTTP-level 429 is a rate limit too, and the generic exception path
                # backs off in fractions of a second — far too fast when the pool is a
                # single endpoint and there is nothing to rotate to. Sleep like a rate
                # signal, because that is exactly what it is.
                if resp.status_code in (429, 503):
                    last = f"{url}: HTTP {resp.status_code}"
                    time.sleep(2.0 * (i + 1))
                    continue
                resp.raise_for_status()
                j = resp.json()
                if "error" in j:
                    kind = classify(j["error"])
                    last = f"{url}: {j['error']}"
                    if kind == "dead":
                        self._dead.add(url)      # never ask this one again
                        continue
                    if kind == "range":
                        # One node's range cap is not every node's. Rotate first and only
                        # declare the window too large if EVERY endpoint says so —
                        # otherwise a single stingy node makes the caller split a window
                        # that the next endpoint would have served whole.
                        rng += 1
                        continue
                    if kind == "rate":
                        time.sleep(1.5 * (i + 1))     # back off, do NOT split the window
                        continue
                    if kind == "pruned":
                        # The question did go unanswered, so it counts as refused — but
                        # rotating to another pruned node cannot change the answer.
                        CENSUS.refused[method] += 1
                        raise PrunedStateError(
                            f"{method} asked a pruned node for historical state "
                            f"({j['error']}). Use an archive pool such as "
                            f"Client(LOG_EPS[chain]); retrying will not help.")
                    if kind == "revert":
                        # The chain answered. Every other endpoint will answer the same,
                        # so stop here instead of burning the rotation on it.
                        CENSUS.answered[method] += 1
                        CENSUS.reverted[method] += 1
                        raise RevertError(f"{method} reverted :: {j['error']}",
                                          data=(j["error"].get("data")
                                                if isinstance(j["error"], dict) else None))
                    continue
                if "result" not in j:
                    last = f"{url}: reply had neither result nor error"
                    continue
                if j["result"] is None:
                    last = f"{url}: result=null"      # never hand None to a caller
                    continue
                return self._answered(method, j["result"])
            except (RangeError, RevertError, PrunedStateError):
                raise                 # none of these improves on another endpoint
            except Exception as e:
                last = f"{url}: {e}"
            time.sleep(0.35 * (i + 1))
        # redact(): `last` carries the endpoint URL and whatever the transport said,
        # and requests puts the full URL — key included — into its own messages too.
        if rng and rng >= min(tries, len(self.endpoints)):
            CENSUS.refused[method] += 1
            raise RangeError(redact(f"every endpoint refused the range :: {last}"))
        CENSUS.refused[method] += 1
        raise RuntimeError(redact(f"rpc failed [{method}] :: {last}"))

    def _answered(self, method, result):
        CENSUS.answered[method] += 1
        if isinstance(result, list) and not result:
            CENSUS.empty[method] += 1
        return result

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
        # Every endpoint refused or mangled the batch. Serial is slower by the
        # batch factor but returns the same answer; raising here would abort a
        # depth run that was one retry from finishing. Callers must never have to
        # choose between "batching works" and "no data".
        try:
            return [self.call(m, p) for m, p in reqs]
        except Exception as e:
            raise RuntimeError(redact(f"batch failed :: {last} ; serial fallback also "
                                      f"failed :: {e}"))

    def eth_call(self, to, data, block="latest"):
        return self.call("eth_call", [{"to": to, "data": data}, block])

    def erc20_balance(self, token, holder, dec=18, block="latest"):
        return int(self.eth_call(token, "0x70a08231" + holder[2:].rjust(64, "0"), block), 16) / 10 ** dec

    def block_number(self):
        return int(self.call("eth_blockNumber", []), 16)


def s256(v):
    """Two's-complement decode of a full 256-bit ABI word. Use for every signed return."""
    return v - (1 << 256) if v >= (1 << 255) else v


class PinnedClient:
    """A Client whose every `latest` is rewritten to one fixed block.

    A tool that reads "latest" in thirty places cannot be pinned by threading a block
    argument through each of them, and a half-pinned run is worse than an unpinned one:
    it mixes two states and reports them as one. The previous audit's depth figures
    reproduced at a tick that was not the snapshot block's, because the profile was read
    at latest while the snapshot was named elsewhere. Wrap the ARCHIVE pool in this and
    every call lands on the same block — pruned nodes cannot serve it (PrunedStateError).
    """

    def __init__(self, client, block):
        self._c = client
        self.block = block if isinstance(block, str) else hex(block)

    def _pin(self, params):
        return [self.block if p == "latest" else p for p in params]

    def call(self, method, params, *a, **kw):
        return self._c.call(method, self._pin(params), *a, **kw)

    def batch(self, reqs, *a, **kw):
        return self._c.batch([(m, self._pin(p)) for m, p in reqs], *a, **kw)

    def eth_call(self, to, data, block="latest"):
        return self.call("eth_call", [{"to": to, "data": data}, block])

    def erc20_balance(self, token, holder, dec=18, block="latest"):
        return int(self.eth_call(token, "0x70a08231" + holder[2:].rjust(64, "0"),
                                 block), 16) / 10 ** dec

    def block_number(self):
        return int(self.block, 16)

    def __getattr__(self, name):
        return getattr(self._c, name)


# Multicall3, so a pinned full-range scan fits inside a public archive quota. A V3 pool
# with tickSpacing 1 has ~6,932 bitmap words; at 100 per JSON-RPC batch that is 70 heavy
# requests and the shared archive key ran out of quota partway through. aggregate3 packs
# hundreds of calls into ONE eth_call. allowFailure is FALSE on every call, so one bad
# sub-call reverts the whole thing instead of quietly returning an empty word that would
# read as "no ticks here". The address is the widely deployed canonical one, but it is
# NOT trusted for that: multicall() proves it — code present, and a probe call returns
# byte-for-byte what a direct eth_call returns — before using it (pitfall #22).
MULTICALL3 = "0xca11bde05977b3631167028862be2a173976ca11"
_AGG3 = "0x82ad56cb"          # aggregate3((address,bool,bytes)[])
_MC_OK = {}


def _enc_agg3(calls):
    n = len(calls)
    heads, body, off = [], [], 32 * n
    for to, data in calls:
        d = bytes.fromhex(data[2:])
        pad = (32 - len(d) % 32) % 32
        el = (to[2:].lower().rjust(64, "0") + "0" * 64 + f"{0x60:064x}"
              + f"{len(d):064x}" + d.hex() + "00" * pad)
        heads.append(f"{off:064x}")
        body.append(el)
        off += len(el) // 2
    return _AGG3 + f"{0x20:064x}" + f"{n:064x}" + "".join(heads) + "".join(body)


def _dec_agg3(ret):
    h = ret[2:]
    word = lambda i: int(h[i * 64:(i + 1) * 64], 16)
    n = word(1)
    base = 2 * 64                                    # hex offset where element offsets start
    out = []
    for k in range(n):
        eo = base + int(h[base + k * 64: base + (k + 1) * 64], 16) * 2
        ok = int(h[eo:eo + 64], 16)
        ln = int(h[eo + 128:eo + 192], 16)
        data = h[eo + 192: eo + 192 + ln * 2]
        if not ok:
            raise RuntimeError("multicall sub-call failed despite allowFailure=false")
        out.append("0x" + data)
    return out


def multicall(client, calls, block="latest", chunk=400, probe=None):
    """Results of [(to, data), ...] via Multicall3, in order. Raises if it cannot prove
    Multicall3 works on this client — callers fall back to plain batching."""
    key = id(client)
    if key not in _MC_OK:
        code = client.call("eth_getCode", [MULTICALL3, block]) or "0x"
        if code in ("0x", "0x0"):
            raise RuntimeError("no Multicall3 code at the canonical address on this chain")
        if probe:
            direct = client.call("eth_call", [{"to": probe[0], "data": probe[1]}, block])
            via = _dec_agg3(client.call("eth_call", [{"to": MULTICALL3,
                                         "data": _enc_agg3([probe])}, block]))[0]
            if int(direct, 16) != int(via, 16):
                raise RuntimeError("Multicall3 probe disagrees with a direct eth_call")
        _MC_OK[key] = True
    out = []
    for i in range(0, len(calls), chunk):
        part = calls[i:i + chunk]
        out += _dec_agg3(client.call("eth_call", [{"to": MULTICALL3,
                                       "data": _enc_agg3(part)}, block]))
    return out
