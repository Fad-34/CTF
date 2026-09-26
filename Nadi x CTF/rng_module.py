
import hashlib

A = 6364136223846793005
C = 1442695040888963407
M = 2 ** 64


class LegacyEntropySource:

    def __init__(self, state):
        self.state = state & 0xFFFFFFFFFFFFFFFF

    def _step(self):
        self.state = (A * self.state + C) % M
        return self.state

    def next_nonce(self, order):

        state = self._step()
        digest = hashlib.sha256(state.to_bytes(8, "big")).digest()
        val = int.from_bytes(digest, "big") % order
        return val or 1
