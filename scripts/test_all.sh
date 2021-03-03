#!/bin/bash
set -o nounset
set -o errexit

if [ ! -d streaming ]; then
	echo "Folder 'streaming' does not exist. Are you in the project root?"
        exit 1
fi

DEFAULT_NUM_TESTS=0  # 0 means all available test cases

NUM_TEST_CASES=${1:-$DEFAULT_NUM_TESTS}

for target in elf/crypto_sign_*test.elf; do
	echo "Flashing ${target}"
	openocd -f nucleo-f2.cfg -c "program ${target} exit"
	echo "Sarting tests for ${target}"
	python3 streaming/test.py -n $NUM_TEST_CASES $target||(echo "A test failed. Exiting." && exit 1)
done
