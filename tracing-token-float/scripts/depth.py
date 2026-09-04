"""Uniswap-V3-family liquidity profile, reserve self-check, and sell simulator.

Works on Uniswap V3, PancakeSwap V3, Aerodrome Slipstream and similar forks.

    from rpc import Client, BASE
    from depth import Pool
    p = Pool(Client(BASE), "0xpool...", dec0=18, dec1=6)
    print(p.selfcheck())            # already run during construction; inspect the numbers
    print(p.sell(1_000_000))

Answers "if they dumped, what would they actually get?" — not "what is it worth at
mark price". In thin markets those differ by orders of magnitude.
"""
from rpc import s256

MIN_TICK, MAX_TICK = -887272, 887272

SEL = dict(slot0="0x3850c7bd", liquidity="0x1a686502", tickSpacing="0xd0c93a7c",
           fee="0xddca3f43", token0="0x0dfe1681", token1="0xd21220a7",
           bitmap="0x5339c296", ticks="0xf30dba93")


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
            raise InconsistentState(
                f"pool {addr}: profile does not reconstruct reserves after {retries} scans "
                f"(token0 {last['err0_pct']:+.1f}%, token1 {last['err1_pct']:+.1f}%). "
                f"Widen span_down/span_up if the book extends past the scan window; "
                f"a negative model means a decode bug; heavy JIT churn may need block=hex(n).")

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
            [("eth_call", [{"to": self.a, "data": SEL["bitmap"] + f"{_u256(w):064x}"}, b])
             for w in wps]))))
        ticks = sorted(((w << 8) + i) * self.ts
                       for w, v in words.items() if v for i in range(256) if v >> i & 1)
        raw = self.c.batch([("eth_call", [{"to": self.a,
                            "data": SEL["ticks"] + f"{_u256(t):064x}"}, b]) for t in ticks])
        # word1 is int128, but ABI encoding sign-extends it into the full 256-bit word.
        # Decoding it as 128-bit turns every negative liquidityNet into ~1e38.
        self.net = {t: s256(int(r[2:][64:128], 16)) for t, r in zip(ticks, raw)}
        self.ticks = ticks

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
            if chain <= 0:
                return -1e-9 <= model <= 1e-9
            # Model must never EXCEED the balance (fees inflate the balance, not positions)
            # and must not fall far short — a large shortfall means the window was too narrow.
            return 0 <= model <= chain * 1.05 and model >= chain * 0.75
        return dict(model0=m0, chain0=self.reserve0, model1=m1, chain1=self.reserve1,
                    err0_pct=(m0 / self.reserve0 - 1) * 100 if self.reserve0 else 0.0,
                    err1_pct=(m1 / self.reserve1 - 1) * 100 if self.reserve1 else 0.0,
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
        rem, out = total, 0.0
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
                    rem -= L * (1 / end - 1 / sqrtP) / (1 - f)
                    out, sqrtP, capped = cap, end, True
                    break
                out += seg
                if after_fee < dx:                        # order fills inside this step
                    sqrtP, rem = end, 0
                    break
                rem -= dx / (1 - f)
            sqrtP = sn
            L -= self.net[t]
        filled = (total - max(rem, 0)) / 10 ** self.d0
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
        token1-denominated price (1/P) falls. Liquidity crossings flip sign too.
        """
        total = amount1 * 10 ** self.d1
        rem, out = total, 0.0
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
                    rem -= L * (end - sqrtP) / (1 - f)
                    out, sqrtP, capped = cap, end, True
                    break
                out += seg
                if after_fee < dy:
                    sqrtP, rem = end, 0
                    break
                rem -= dy / (1 - f)
            sqrtP = sn
            L += self.net[t]
        filled = (total - max(rem, 0)) / 10 ** self.d1
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

    def curve(self, sizes):
        return [self.sell(s) for s in sizes]
