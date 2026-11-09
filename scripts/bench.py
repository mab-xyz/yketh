"""Time the card: connect, PIN, public key, and N signatures in one session (YKETH_PIN[_FILE])."""

from __future__ import annotations

import os
import statistics
import sys
import time

from yketh._card import open_card
from yketh._eth import sign_digest
from yketh.cli import _pin


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    pin = _pin("YKETH_PIN", "PIN: ")
    t0 = time.perf_counter()
    with open_card() as card:
        t1 = time.perf_counter()
        card.verify_pin(pin)
        t2 = time.perf_counter()
        point = card.point()
        t3 = time.perf_counter()
        ms = []
        for _ in range(n):
            digest = os.urandom(32)
            a = time.perf_counter()
            sign_digest(digest, card.sign_digest, point)
            ms.append((time.perf_counter() - a) * 1000)
    ms.sort()
    print(f"connect {1000 * (t1 - t0):.0f} ms, verify PIN {1000 * (t2 - t1):.0f} ms, "
          f"public key {1000 * (t3 - t2):.0f} ms")
    print(f"sign+recover over {n}: min {ms[0]:.0f}, median {statistics.median(ms):.0f}, "
          f"max {ms[-1]:.0f} ms")


if __name__ == "__main__":
    main()
