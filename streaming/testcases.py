import pathlib
import os
import logging

TEST_DATA_DIR = "test_data"
log = logging.getLogger(__name__)


class TestCase:
    def __init__(self, name, path):
        self.kv_store = {"name": name}

        with open(path) as f:
            while line := f.readline():
                key, value = line.split(":")
                key = key.strip().lower()
                value = value.strip().lower()
                self.kv_store[key] = bytes.fromhex(value)
            log.debug("Loaded test case from %s.", path)


class TestCases:
    def __init__(self, target, num=0):
        self.target = target
        self.target_dir = pathlib.Path(__file__).parent / TEST_DATA_DIR / target

        if not os.path.exists(self.target_dir):
            msg = f"No testcases for {self.target_dir} exist."
            log.error(msg)
            raise ValueError(msg)

        self.test_cases = sorted(os.listdir(self.target_dir))
        self.pos = 0

        if num:
            if num < len(self.test_cases):
                self.test_cases = self.test_cases[:num]
            elif num > len(self.test_cases):
                log.info(
                    "Only %d test cases available for %s. %d test cases were requested.",
                    len(self.test_cases), target, num
                )

    def __iter__(self):
        return self

    def __getitem__(self, item):
        if type(item) is not slice:
            raise ValueError("Only slicing is supported on TestCases.")
        if item.step is not None:
            raise ValueError("Slicing is only supported with step size 1.")

        t = TestCases(self.target)
        t.test_cases = t.test_cases[item.start:item.stop]
        return t

    def __len__(self):
        return len(self.test_cases)

    def __next__(self):
        if self.pos >= len(self.test_cases):
            raise StopIteration()
        tc = TestCase(self.test_cases[self.pos], self.target_dir / self.test_cases[self.pos])
        self.pos += 1
        return tc.kv_store




