"""Uniswap-V3-family liquidity profile, reserve self-check, and sell simulator.

Works on Uniswap V3, PancakeSwap V3, Aerodrome Slipstream and similar forks.

    from rpc import Client, BASE
    from depth import Pool
    p = Pool(Client(BASE), "0xpool...", dec0=18, dec1=6)
    print(p.selfcheck())            # already run during construction; inspect the numbers
    print(p.sell(1_000_000))

Answers "if they dumped, what would they actually get?" — not "what is it worth at
mark price". In thin markets those differ by orders of magnitude.

Singleton-pool AMMs — Pancake Infinity CL and Uniswap V4 — keep every pool inside one
manager contract, keyed by a 32-byte poolId, with no per-pool ERC-20 balance:

    from depth import InfinityPool, V4Pool
    p = InfinityPool(Client(BSC), "0xCLPoolManager...", "0xPOOL_ID...", 18, 18)
    q = V4Pool(Client(BSC), "0xPoolManager...", (c0, c1, fee, tickSpacing, hooks), 18, 18)

Same identities, same simulator. See SingletonPool for what the reserve check can and
cannot say there.
"""
import math
from Crypto.Hash import keccak as _k
from rpc import s256
from topics import selector

MIN_TICK, MAX_TICK = -887272, 887272

SEL = dict(slot0="0x3850c7bd", liquidity="0x1a686502", tickSpacing="0xd0c93a7c",
           fee="0xddca3f43", token0="0x0dfe1681", token1="0xd21220a7",
           bitmap="0x5339c296", ticks="0xf30dba93",
           protocolFees="0x1ad8b03b")


def _u256(x):
    return x & ((1 << 256) - 1)


class InconsistentState(RuntimeError):
    """Profile and active liquidity described different pool states."""


class Pool:
    """A pool's liquidity book, reconstructed from tickBitmap + ticks.

    slot0/liquidity/tickBitmap/ticks are separate RPC calls. On a pool with JIT market
    makers, positions can be minted and burned between them, leaving active liquidity
    from one state against a tick set from another — the integration then walks off the
    end of the book and produces negative reserves.

    Rather than demand that nothing move (hopeless: any swap shifts sqrtPrice), the
    constructor validates the invariant that actually matters — that the profile
    reconstructs the pool's real reserves — and rescans if it doesn't. Pass
    block=hex(n) against an archive node to pin instead; most public Base/BSC nodes
    are pruned and reject historical eth_call.
    """

    def __init__(self, client, addr, dec0, dec1, span_down=None, span_up=None,
                 batch=120, block=None, retries=3):
        self.c, self.a, self.d0, self.d1 = client, addr, dec0, dec1
        b = block or "latest"
        last = None
        for attempt in range(retries):
            self._read(b, dec0, dec1, span_down, span_up, batch)
            last = self.selfcheck()
            if last["ok"] or block is not None:
                break
        self.check = last
        if not last["ok"]:
            why = []
            if not last["id_sum_zero"]:
                why.append(f"sum(liquidityNet)={last['sum_net']} != 0 (book truncated)")
            if not last["id_active_liquidity"]:
                why.append("below-price liquidityNet != liquidity() (book truncated)")
            if last["model0"] < 0 or last["model1"] < 0:
                why.append("negative model (decode bug)")
            if last["model0"] > last["chain0"] * 1.001:
                why.append(f"model0 exceeds balance by "
                           f"{last['model0'] - last['chain0']:.6g} (decode bug or stale read)")
            if last["model1"] > last["chain1"] * 1.001:
                why.append(f"model1 exceeds balance by "
                           f"{last['model1'] - last['chain1']:.6g} (decode bug or stale read)")
            raise InconsistentState(
                f"pool {addr}: " + "; ".join(why or ["unknown"]) +
                f" [after {retries} scans; token0 {last['err0_pct']:+.2f}%, "
                f"token1 {last['err1_pct']:+.2f}%, {last['ticks']} ticks]. "
                f"A model exceeding the balance or going negative is a decode bug; "
                f"a broken identity means the tick scan did not cover the whole book; "
                f"heavy JIT churn between the slot0 and ticks reads needs block=hex(n).")

    def _read(self, b, dec0, dec1, down, up, batch):
        s0 = self.c.eth_call(self.a, SEL["slot0"], b)[2:]
        self.sqrtP = int(s0[:64], 16) / 2 ** 96
        self.tick = s256(int(s0[64:128], 16))
        self.L0 = int(self.c.eth_call(self.a, SEL["liquidity"], b), 16)
        self.ts = s256(int(self.c.eth_call(self.a, SEL["tickSpacing"], b), 16))
        self.fee = int(self.c.eth_call(self.a, SEL["fee"], b), 16)
        self.token0 = "0x" + self.c.eth_call(self.a, SEL["token0"], b)[-40:]
        self.token1 = "0x" + self.c.eth_call(self.a, SEL["token1"], b)[-40:]
        self.reserve0 = self.c.erc20_balance(self.token0, self.a, dec0, b)
        self.reserve1 = self.c.erc20_balance(self.token1, self.a, dec1, b)
        # Accrued protocol fees sit in the ERC-20 balance but back no swap. Reading them
        # turns "the model is 99.8% short" from an alarm into an explained residual.
        # Not every V3 fork exposes protocolFees(); absence is not an error.
        try:
            r = self.c.eth_call(self.a, SEL["protocolFees"], b)[2:]
            self.pfee0 = int(r[:64], 16) / 10 ** dec0
            self.pfee1 = int(r[64:128], 16) / 10 ** dec1
        except Exception:
            self.pfee0 = self.pfee1 = None
        self._scan(down, up, batch, b)

    def _scan(self, down, up, batch, b):
        # Scan the FULL valid tick range by default. The two structural identities
        # (sum(liquidityNet) == 0, and the below-price sum == active liquidity) only
        # hold over a complete profile — and they are the only checks that catch a
        # truncated window, which otherwise reports the bottom of the scanned range as
        # a price floor. Cost is bounded: word count is 2*887272/tickSpacing/256, so
        # ~35 words at tickSpacing 200 and ~6,932 at tickSpacing 1.
        lo = (MIN_TICK // self.ts) >> 8 if down is None else ((self.tick - down) // self.ts) >> 8
        hi = (MAX_TICK // self.ts) >> 8 if up is None else ((self.tick + up) // self.ts) >> 8
        wps = list(range(lo, hi + 1))
        words = dict(zip(wps, (int(r, 16) for r in self.c.batch(
            [self._bitmap_call(w, b) for w in wps]))))
        ticks = sorted(((w << 8) + i) * self.ts
                       for w, v in words.items() if v for i in range(256) if v >> i & 1)
        raw = self.c.batch([self._tick_call(t, b) for t in ticks])
        self.net = {t: self._tick_net(r) for t, r in zip(ticks, raw)}
        self.ticks = ticks

    # The three reads _scan makes, separated so a pool that is not its own contract
    # (SingletonPool below) can swap the transport and keep every identity and the
    # simulator unchanged.
    def _bitmap_call(self, w, b):
        return ("eth_call", [{"to": self.a, "data": SEL["bitmap"] + f"{_u256(w):064x}"}, b])

    def _tick_call(self, t, b):
        return ("eth_call", [{"to": self.a, "data": SEL["ticks"] + f"{_u256(t):064x}"}, b])

    @staticmethod
    def _tick_net(r):
        # word1 is int128, but ABI encoding sign-extends it into the full 256-bit word.
        # Decoding it as 128-bit turns every negative liquidityNet into ~1e38.
        return s256(int(r[2:][64:128], 16))

    @property
    def price(self):
        return self.sqrtP ** 2 * 10 ** (self.d0 - self.d1)

    def selfcheck(self):
        """Integrate the profile back into reserves and compare with real balances.

        The model reconstructs only what sits in positions. Uncollected and protocol fees
        inflate the ERC-20 balance without ever backing a swap, so model <= chain is
        normal and the shortfall grows on thin, high-volume pools. A model that EXCEEDS
        the balance, or goes negative, is the decode/scan bug this check exists to catch.
        """
        a1, L, sp = 0.0, float(self.L0), self.sqrtP
        for t in sorted((t for t in self.ticks if t <= self.tick), reverse=True):
            sn = 1.0001 ** (t / 2)
            if sn < sp:
                a1 += L * (sp - sn)
                sp = sn
            L -= self.net[t]
        a0, L, sp = 0.0, float(self.L0), self.sqrtP
        for t in sorted(t for t in self.ticks if t > self.tick):
            sn = 1.0001 ** (t / 2)
            if sn > sp:
                a0 += L * (1 / sp - 1 / sn)
                sp = sn
            L += self.net[t]
        m0, m1 = a0 / 10 ** self.d0, a1 / 10 ** self.d1

        # Two structural identities that hold for ANY complete V3 profile. They catch
        # window truncation, which the reserve comparison alone does not: a scan that
        # stops short still reconstructs plausible reserves, then silently reports the
        # bottom of the scanned range as a price floor.
        net_all = sum(self.net.values())
        net_below = sum(v for t, v in self.net.items() if t <= self.tick)
        id_sum_zero = abs(net_all) <= max(1, abs(self.L0)) * 1e-9
        id_active = abs(net_below - self.L0) <= max(1, abs(self.L0)) * 1e-9

        def band(model, chain):
            """Only the two directions that are ALWAYS a bug.

            A ratio floor looks like it catches a truncated window, and does not. It
            fails both ways: a pool whose balance is 99.8% accrued protocol fees has a
            model that is exactly right and a ratio of 0.002, while a book truncated
            around a full-range position still reconstructs reserves to within 1.5%.
            Truncation is caught losslessly by the two identities below, which are
            exact. So test only: never negative, never exceeding the balance (fees
            inflate the balance, never the positions).
            """
            if chain <= 0:
                return -1e-9 <= model <= 1e-9
            return 0 <= model <= chain * 1.001 + 1e-9
        res0, res1 = self.reserve0 - m0, self.reserve1 - m1

        def explained(residual, pfee):
            """Share of the model/balance gap that accrued protocol fees account for."""
            if pfee is None or residual <= 0:
                return None
            return min(pfee / residual, 1.0) if residual > 0 else None

        return dict(model0=m0, chain0=self.reserve0, model1=m1, chain1=self.reserve1,
                    err0_pct=(m0 / self.reserve0 - 1) * 100 if self.reserve0 else 0.0,
                    err1_pct=(m1 / self.reserve1 - 1) * 100 if self.reserve1 else 0.0,
                    residual0=res0, residual1=res1,
                    pfee0=self.pfee0, pfee1=self.pfee1,
                    explained0=explained(res0, self.pfee0),
                    explained1=explained(res1, self.pfee1),
                    sum_net=net_all, id_sum_zero=id_sum_zero, id_active_liquidity=id_active,
                    ok=(band(m0, self.reserve0) and band(m1, self.reserve1)
                        and id_sum_zero and id_active),
                    ticks=len(self.ticks))

    def sell(self, amount0):
        """Sell `amount0` of token0. Reports what is ACTUALLY fillable, not what was asked.

        Two independent stops, and both must reduce the reported fill:
          - liquidity exhausted: below the lowest initialised tick there are no bids
          - quote exhausted: proceeds can never exceed the pool's token1 balance

        On the quote stop, solve for the price where cumulative output equals the
        balance rather than truncating the total afterwards. Truncating reports the
        full requested size as filled while paying out a capped amount — an average
        price that no one could ever get.
        """
        total = amount0 * 10 ** self.d0
        # Track what was CONSUMED, never total-minus-remainder. Differencing two nearly
        # equal floats reported filled=0.000000 on a true fill of 0.004073 when the probe
        # size dwarfed the book — and the drain probe is deliberately such a size.
        rem, out, used = total, 0.0, 0.0
        sqrtP, L, f = self.sqrtP, float(self.L0), self.fee / 1e6
        cap = self.reserve1 * 10 ** self.d1
        capped = False
        for t in sorted((t for t in self.ticks if t <= self.tick), reverse=True):
            if rem <= 0:
                break
            sn = 1.0001 ** (t / 2)
            if sn >= sqrtP:
                L -= self.net[t]
                continue
            if L > 0:
                after_fee = rem * (1 - f)
                dx = L * (1 / sn - 1 / sqrtP)
                end = 1 / (1 / sqrtP + after_fee / L) if after_fee < dx else sn
                seg = L * (sqrtP - end)
                if out + seg >= cap:                      # quote runs out inside this step
                    end = sqrtP - (cap - out) / L
                    d = L * (1 / end - 1 / sqrtP) / (1 - f)
                    rem -= d; used += d
                    out, sqrtP, capped = cap, end, True
                    break
                out += seg
                if after_fee < dx:                        # order fills inside this step
                    used += rem
                    sqrtP, rem = end, 0
                    break
                rem -= dx / (1 - f); used += dx / (1 - f)
            sqrtP = sn
            L -= self.net[t]
        filled = min(used, total) / 10 ** self.d0
        proceeds = out / 10 ** self.d1
        end_px = sqrtP ** 2 * 10 ** (self.d0 - self.d1)
        return dict(requested=amount0, filled=filled, proceeds=proceeds,
                    avg=proceeds / filled if filled else 0.0, end_price=end_px,
                    drawdown_pct=(end_px / self.price - 1) * 100,
                    partial=filled < amount0 * 0.999,
                    stop="quote exhausted" if capped
                         else ("liquidity exhausted" if rem > 0 else "filled"))


    # ---------- selling token1 (walks the book upward) ----------
    def sell1(self, amount1):
        """Sell `amount1` of token1 for token0.

        A token is token1 whenever its address sorts above its quote asset's, which
        is arbitrary — so half of all tokens can only be sold in this direction. The
        book walks UP: adding token1 makes token0 scarcer, sqrtPrice rises, and the
        token0-denominated price of token1 (1/P) falls. Liquidity crossings flip sign too.
        """
        total = amount1 * 10 ** self.d1
        rem, out, used = total, 0.0, 0.0
        sqrtP, L, f = self.sqrtP, float(self.L0), self.fee / 1e6
        cap = self.reserve0 * 10 ** self.d0
        capped = False
        for t in sorted(t for t in self.ticks if t > self.tick):
            if rem <= 0:
                break
            sn = 1.0001 ** (t / 2)
            if sn <= sqrtP:
                L += self.net[t]
                continue
            if L > 0:
                after_fee = rem * (1 - f)
                dy = L * (sn - sqrtP)                     # token1 the step absorbs
                end = sqrtP + after_fee / L if after_fee < dy else sn
                seg = L * (1 / sqrtP - 1 / end)           # token0 paid out
                if out + seg >= cap:                      # token0 side runs dry
                    end = 1 / (1 / sqrtP - (cap - out) / L)
                    d = L * (end - sqrtP) / (1 - f)
                    rem -= d; used += d
                    out, sqrtP, capped = cap, end, True
                    break
                out += seg
                if after_fee < dy:
                    used += rem
                    sqrtP, rem = end, 0
                    break
                rem -= dy / (1 - f); used += dy / (1 - f)
            sqrtP = sn
            L += self.net[t]
        filled = min(used, total) / 10 ** self.d1
        proceeds = out / 10 ** self.d0
        end_px = 1 / (sqrtP ** 2 * 10 ** (self.d0 - self.d1))
        return dict(requested=amount1, filled=filled, proceeds=proceeds,
                    avg=proceeds / filled if filled else 0.0, end_price=end_px,
                    drawdown_pct=(end_px / self.price1 - 1) * 100,
                    partial=filled < amount1 * 0.999,
                    stop="quote exhausted" if capped
                         else ("liquidity exhausted" if rem > 0 else "filled"))

    @property
    def price1(self):
        """Price of token1 denominated in token0."""
        return 1 / self.price

    def excluding(self, positions):
        """A counterfactual book with the named positions removed.

        This is the ONLY correct way to answer "what is left if they withdraw". The
        subtraction people reach for instead — total quote in the book minus the quote
        inside their positions — answers a different question, and on a position that
        straddles spot it is wrong by the entire bid. Ownership of liquidity does not
        change what an AMM pays a seller; only removing the liquidity does.

        `positions`: iterable of (tick_lower, tick_upper, liquidity), exactly the rows
        positions.py enumerates. Returns a NEW Pool; the original is untouched.
        """
        import copy
        p = copy.copy(self)
        p.net, p.L0 = dict(self.net), self.L0
        for tl, tu, liq in positions:
            liq = int(liq)
            if tl not in p.net or tu not in p.net:
                raise InconsistentState(
                    f"position [{tl},{tu}] has ticks outside the scanned profile — the "
                    f"scan was truncated, so nothing may be subtracted from it")
            p.net[tl] -= liq
            p.net[tu] += liq
            if tl <= self.tick < tu:
                p.L0 -= liq
        if p.L0 < 0:
            raise InconsistentState(
                f"removing those positions takes active liquidity negative ({p.L0}): the "
                f"positions exceed the book, so one of the two measurements is wrong. "
                f"Publish neither.")
        p.ticks = sorted(p.net)
        c = p.selfcheck()
        if not (c["id_sum_zero"] and c["id_active_liquidity"]):
            raise InconsistentState(
                f"counterfactual book fails its structural identities "
                f"(sum_net={c['sum_net']}) — the subtraction was not equal-and-opposite")
        # The pool's ERC-20 balances still contain the withdrawn tokens, so they are not
        # this book's reserves. Re-integrating gives what the pool would actually hold.
        p.reserve0, p.reserve1 = c["model0"], c["model1"]
        p.check = p.selfcheck()
        return p

    def curve(self, sizes, token1=False):
        """Depth curve. Pass token1=True when the token you are selling is the pool's
        token1 — otherwise this charts the wrong side of the book for half of all
        tokens, silently."""
        f = self.sell1 if token1 else self.sell
        return [f(s) for s in sizes]


# ---------------------------------------------------------------- singleton pools
def _keccak(b):
    h = _k.new(digest_bits=256)
    h.update(b)
    return h.digest()


def _w(x):
    """One 32-byte ABI word, two's complement for negatives."""
    return _u256(x).to_bytes(32, "big")


def _swap_fee(protocol_fee, lp_fee):
    """Total swap fee in pips from slot0's two fields, the way both singletons charge it.

    protocolFee packs two 12-bit directional fees (low = zeroForOne, high = oneForZero)
    and is applied on top of the LP fee: p + lp - p*lp/1e6. The simulator takes one fee
    for both directions, so this uses the LARGER of the two — a seller is never told
    they get more than they would."""
    p = max(protocol_fee & 0xFFF, protocol_fee >> 12 & 0xFFF)
    return p + lp_fee - p * lp_fee // 1_000_000


class SingletonPool(Pool):
    """A concentrated-liquidity pool that lives inside a singleton manager.

    The book is the same V3 book and every structural identity still holds, so the
    whole Pool machinery applies. Two things do not carry over, and both matter:

      - There is no per-pool token balance. The manager's vault holds every pool's
        tokens together, so `reserve0/1` here are the VAULT's balances: an upper bound,
        not this pool's reserves. The band check keeps its value as a decode check
        (a model above the vault's whole balance is a bug) and loses it as a reserve
        check; err%/residual are against the vault and mean nothing. The two
        structural identities are the real gate.
      - A wrong poolId or manager does not error. Every read returns zeros, and an
        empty book satisfies both identities vacuously — a pool that does not exist
        passes selfcheck. So each subclass proves the key hashes to the poolId, and
        slot0 must be non-zero with a tick that agrees with its own sqrtPrice.

    A non-zero `hooks` address is printed, never ignored: a hook can take a fee or
    reroute a swap entirely, and then the book is not what a seller receives.
    """

    def __init__(self, client, manager, pool_id, dec0, dec1, **kw):
        self.pid = pool_id.lower()
        self.hooks = None
        super().__init__(client, manager.lower(), dec0, dec1, **kw)

    def _read(self, b, dec0, dec1, down, up, batch):
        self._load_key(b)                               # token0/1, ts, hooks; proves pid
        sqrt_x96, self.tick, self.protocol_fee, self.lp_fee = self._slot0(b)
        if sqrt_x96 == 0:
            raise InconsistentState(
                f"pool {self.pid} on {self.a}: slot0 is zero — not initialised, or the "
                f"manager is wrong. Every other read would be zeros too and pass the "
                f"identities vacuously.")
        self.sqrtP = sqrt_x96 / 2 ** 96
        want = math.floor(math.log(self.sqrtP ** 2) / math.log(1.0001))
        if abs(want - self.tick) > 1:
            raise InconsistentState(
                f"pool {self.pid}: slot0 tick {self.tick} disagrees with its own sqrtPrice "
                f"(implies {want}) — slot0 was decoded from the wrong word or slot")
        self.fee = _swap_fee(self.protocol_fee, self.lp_fee)
        self.L0 = self._liquidity(b)
        vault = self._vault(b)
        self.reserve0 = self._held(self.token0, vault, dec0, b)
        self.reserve1 = self._held(self.token1, vault, dec1, b)
        self.pfee0 = self.pfee1 = None
        self._scan(down, up, batch, b)

    def _held(self, token, vault, dec, b):
        if int(token, 16) == 0:                       # native currency, not an ERC-20
            return int(self.c.call("eth_getBalance", [vault, b]), 16) / 10 ** dec
        return self.c.erc20_balance(token, vault, dec, b)

    def selfcheck(self):
        d = super().selfcheck()
        d["reserve_scope"] = "vault (every pool) — upper bound only"
        d["hooks"] = self.hooks
        return d


class InfinityPool(SingletonPool):
    """Pancake Infinity CL: CLPoolManager exposes per-poolId getters directly."""

    SIG = dict(slot0="getSlot0(bytes32)", liquidity="getLiquidity(bytes32)",
               key="poolIdToPoolKey(bytes32)", vault="vault()",
               bitmap="getPoolBitmapInfo(bytes32,int16)", tick="getPoolTickInfo(bytes32,int24)")

    def _call(self, name, b, *words):
        data = selector(self.SIG[name]) + self.pid[2:].rjust(64, "0") + "".join(
            w.hex() for w in words)
        return self.c.eth_call(self.a, data, b)

    def _load_key(self, b):
        # PoolKey = (currency0, currency1, hooks, poolManager, fee, parameters), and the
        # poolId IS keccak(abi.encode(key)). Checking that proves both the id and the
        # manager at once: a wrong manager returns a zero key, which hashes to neither.
        k = self._call("key", b)[2:]
        if len(k) < 384 or "0x" + _keccak(bytes.fromhex(k[:384])).hex() != self.pid:
            raise InconsistentState(
                f"poolIdToPoolKey({self.pid}) on {self.a} does not hash back to the poolId "
                f"— wrong poolId, or this is not its CLPoolManager")
        wd = [k[i:i + 64] for i in range(0, 384, 64)]
        self.token0, self.token1 = "0x" + wd[0][24:], "0x" + wd[1][24:]
        self.hooks = "0x" + wd[2][24:]
        if int(self.hooks, 16) == 0:
            self.hooks = None
        if ("0x" + wd[3][24:]).lower() != self.a:
            raise InconsistentState(f"pool {self.pid}: its key names manager 0x{wd[3][24:]}, "
                                    f"not {self.a}")
        ts = int(wd[5], 16) >> 16 & 0xFFFFFF                 # CL parameters bits 16..39
        self.ts = ts - (1 << 24) if ts >= 1 << 23 else ts

    def _slot0(self, b):
        r = self._call("slot0", b)[2:]
        return (int(r[:64], 16), s256(int(r[64:128], 16)),
                int(r[128:192], 16), int(r[192:256], 16))

    def _liquidity(self, b):
        return int(self._call("liquidity", b), 16)

    def _vault(self, b):
        return "0x" + self.c.eth_call(self.a, selector(self.SIG["vault"]), b)[-40:]

    def _bitmap_call(self, w, b):
        return ("eth_call", [{"to": self.a, "data": selector(self.SIG["bitmap"])
                              + self.pid[2:] + f"{_u256(w):064x}"}, b])

    def _tick_call(self, t, b):
        return ("eth_call", [{"to": self.a, "data": selector(self.SIG["tick"])
                              + self.pid[2:] + f"{_u256(t):064x}"}, b])
    # Tick.Info is (liquidityGross, liquidityNet, ...): the V3 word layout, so the
    # inherited _tick_net applies unchanged.


class V4Pool(SingletonPool):
    """Uniswap V4: the PoolManager has no per-pool getters, only `extsload(slot)`.

    State is read from storage directly, at the slots v4-core's StateLibrary derives:
    pools mapping at slot 6; within a pool's state, liquidity at +3, the ticks mapping
    at +4 and the tick bitmap at +5; mapping keys are int256-padded. Those numbers are
    recalled from the library, NOT derived here — which is exactly why _read refuses a
    zero slot0 and a slot0 whose tick disagrees with its sqrtPrice. A wrong base slot
    fails that loudly instead of reading an empty book.

    The manager also stores no PoolKey, so it cannot be looked up from the poolId.
    Pass the key — (currency0, currency1, fee, tickSpacing, hooks) — from the pool's
    Initialize event, a position manager's poolKeys(), or the vault that deployed into
    it; the poolId is derived from it as keccak(abi.encode(key)), and checked against
    `pool_id` when you pass that too.
    """

    POOLS_SLOT, LIQUIDITY_OFFSET, TICKS_OFFSET, BITMAP_OFFSET = 6, 3, 4, 5

    def __init__(self, client, manager, key, dec0, dec1, pool_id=None, **kw):
        c0, c1, fee, ts, hooks = key
        self._key = (c0.lower(), c1.lower(), int(fee), int(ts), hooks.lower())
        pid = "0x" + _keccak(b"".join((_w(int(c0, 16)), _w(int(c1, 16)), _w(int(fee)),
                                       _w(int(ts)), _w(int(hooks, 16))))).hex()
        if pool_id and pool_id.lower() != pid:
            raise InconsistentState(f"key hashes to {pid}, not to the pool_id {pool_id} — "
                                    f"one of the five key fields is wrong")
        super().__init__(client, manager, pid, dec0, dec1, **kw)

    def _load_key(self, b):
        self.token0, self.token1, _, self.ts, hooks = self._key
        self.hooks = hooks if int(hooks, 16) else None
        self._state = int.from_bytes(_keccak(bytes.fromhex(self.pid[2:])
                                             + _w(self.POOLS_SLOT)), "big")

    def _sload(self, slot, b):
        return int(self.c.eth_call(self.a, selector("extsload(bytes32)")
                                   + f"{slot:064x}", b), 16)

    def _mapping(self, key, offset):
        return int.from_bytes(_keccak(_w(key) + _w(self._state + offset)), "big")

    def _slot0(self, b):
        v = self._sload(self._state, b)
        tick = v >> 160 & 0xFFFFFF
        return (v & ((1 << 160) - 1), tick - (1 << 24) if tick >= 1 << 23 else tick,
                v >> 184 & 0xFFFFFF, v >> 208 & 0xFFFFFF)

    def _liquidity(self, b):
        return self._sload(self._state + self.LIQUIDITY_OFFSET, b) & ((1 << 128) - 1)

    def _vault(self, b):
        return self.a                                # the PoolManager holds the tokens

    def _bitmap_call(self, w, b):
        return ("eth_call", [{"to": self.a, "data": selector("extsload(bytes32)")
                              + f"{self._mapping(w, self.BITMAP_OFFSET):064x}"}, b])

    def _tick_call(self, t, b):
        return ("eth_call", [{"to": self.a, "data": selector("extsload(bytes32)")
                              + f"{self._mapping(t, self.TICKS_OFFSET):064x}"}, b])

    @staticmethod
    def _tick_net(r):
        # One packed word: liquidityGross in the low 128 bits, liquidityNet (int128) in
        # the high 128 — NOT the ABI layout of V3's ticks(), which puts net in word 1.
        v = int(r, 16) >> 128
        return v - (1 << 128) if v >= 1 << 127 else v


if __name__ == "__main__":
    import argparse, json
    from rpc import Client, BASE, BSC, ETH
    NETS = {"base": BASE, "bsc": BSC, "eth": ETH}
    p = argparse.ArgumentParser(description="V3 liquidity profile + sell simulator")
    p.add_argument("--chain", required=True, choices=list(NETS))
    where = p.add_mutually_exclusive_group(required=True)
    where.add_argument("--pool", help="a V3-family pool contract")
    where.add_argument("--pool-id", help="a singleton pool's 32-byte poolId (Pancake "
                                          "Infinity CL, or Uniswap V4 with --v4-key)")
    p.add_argument("--manager", help="with --pool-id: the CLPoolManager / PoolManager that "
                                     "holds it. The poolId is proved against it, never assumed")
    p.add_argument("--v4-key", metavar="C0,C1,FEE,TICKSPACING,HOOKS",
                   help="with --pool-id: this is a Uniswap V4 pool, and here is its PoolKey "
                        "(V4 stores none on-chain). Must hash to --pool-id")
    p.add_argument("--dec0", type=int, required=True, help="token0 decimals — read it, never guess")
    p.add_argument("--dec1", type=int, required=True, help="token1 decimals")
    p.add_argument("--sell", type=float, nargs="*", default=[10_000, 100_000, 1_000_000])
    p.add_argument("--token1", action="store_true",
                   help="the token you are selling is the pool's token1")
    p.add_argument("--block", help="hex block to pin to (needs an archive node)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    cli = Client(NETS[a.chain])
    if a.pool:
        pool = Pool(cli, a.pool.lower(), a.dec0, a.dec1, block=a.block)
    elif not a.manager:
        p.error("--pool-id needs --manager: a singleton pool is only defined inside one")
    elif a.v4_key:
        c0, c1, fee, ts, hooks = (x.strip() for x in a.v4_key.split(","))
        pool = V4Pool(cli, a.manager, (c0, c1, int(fee), int(ts), hooks), a.dec0, a.dec1,
                      pool_id=a.pool_id, block=a.block)
    else:
        pool = InfinityPool(cli, a.manager, a.pool_id, a.dec0, a.dec1, block=a.block)
    sell = pool.sell1 if a.token1 else pool.sell
    px = pool.price1 if a.token1 else pool.price
    res = [sell(s) for s in a.sell]
    if a.json:
        print(json.dumps({"check": pool.check, "price": px, "sells": res}, indent=1, default=str))
    else:
        ck = pool.check
        print(f"{a.pool or a.pool_id}  price {px:,.8g}  ticks {ck['ticks']}  fee {pool.fee/1e4:.4g}%")
        print(f"  self-check ok={ck['ok']}  sum(liquidityNet)==0: {ck['id_sum_zero']}  "
              f"below-price==liquidity(): {ck['id_active_liquidity']}")
        print(f"  model/chain  token0 {ck['model0']:,.6g}/{ck['chain0']:,.6g} ({ck['err0_pct']:+.2f}%)"
              f"   token1 {ck['model1']:,.6g}/{ck['chain1']:,.6g} ({ck['err1_pct']:+.2f}%)")
        if ck.get("reserve_scope"):
            print(f"  ! 'chain' is the {ck['reserve_scope']}: the % above is NOT a reserve "
                  f"check here — the two identities are the gate")
        if ck.get("hooks"):
            print(f"  ! hooks {ck['hooks']}: a hook can take a fee or reroute a swap, so the "
                  f"book is not a promise of what a seller receives — read the hook")
        for r in res:
            print(f"  sell {r['requested']:>14,.0f}  filled {r['filled']:>14,.0f}  "
                  f"proceeds {r['proceeds']:>14,.2f}  avg {r['avg']:>12.6g}  "
                  f"after {r['end_price']:>12.8g}  {r['drawdown_pct']:>7.1f}%  {r['stop']}")
