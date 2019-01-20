from typing import List


class Vector:
    def __init__(self, n: List[int]):
        self.n = n

    def __len__(self):
        return len(self.n)