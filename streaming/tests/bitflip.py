import stream
import sys
import logging
from random import randint


class Test:
    passed = False


class _BitflipTest(Test):
    def __init__(self, flip, sm, pk):
        self.flip = bool(flip)
        self.pk = pk
        self.sm = sm
        if flip == "pk":
            self.pk = _BitflipTest.flip_random(pk)
        elif flip == "sm":
            self.sm = _BitflipTest.flip_random(sm)

    @staticmethod
    def flip_random(data):
        pos = randint(0, len(data)-1)
        mask = randint(0, 255)|1
        data = bytearray(data)
        data[pos] ^= mask
        return bytes(data)

    def update_passed(self, valid):
        if self.flip and not valid:
            self.passed = True
        elif not self.flip and valid:
            self.passed = True


class PKBitflipTest(_BitflipTest):
    def __init__(self, sm, pk):
        super().__init__("pk", sm, pk)


class SMBitflipTest(_BitflipTest):
    def __init__(self, sm, pk):
        super().__init__("sm", sm, pk)


class ValidTest(_BitflipTest):
    def __init__(self, sm, pk):
        super().__init__(None, sm, pk)


def main():
    logging.basicConfig(level=logging.INFO)
    scheme = sys.argv[1]

    if scheme not in stream.schemes:
        print("Scheme not included.")
        sys.exit(1)
    vals = stream.schemes[scheme]
    t = _BitflipTest("pk", vals["sm"], vals["pk"])
    s = stream.Stream(t.sm, t.pk)
    s.subscribe_message_type(stream.MessageType.RESULT, t.update_passed)
    s.stream()

    print("Test done, test", "SUCCEEDED" if t.passed else "FAILED")


if __name__ == '__main__':
    main()