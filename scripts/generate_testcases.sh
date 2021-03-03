#!/bin/bash
set -o nounset
set -o errexit

if [ $# -lt 3 ] ; then
    echo "Scheme name, number of testcases or destination missing. Call: $0 SCHEME_NAME NUM_OF_TESTCASES TARGET"
    echo "Example: $0 falcon-512 100 elf/crypto_sign_stream_falcon-512_opt-ct_serial.elf"
    exit 1
fi

SCHEME=$1
NUM_OF_TESTCASES=$2
DEST=streaming/test_data/$(basename $3)

if [ ! -d "${DEST}" ]; then
	echo "The destination directory '${DEST}' does not exist. Creating now."
	mkdir $DEST
fi

NUM_EXISTING_TESTCASES=$(ls ${DEST}|wc -l)

if [ ! -d "pqclean/test" ]; then
	echo "Directory 'pqclean/test' does not exist. Are you in the correct folder?"
	exit 1
fi

cd pqclean/test/
make TYPE=sign SCHEME=${SCHEME} IMPLEMENTATION=clean
cd ../..

echo -e "pk\nsm" > .prefix

let MAX_NUM=${NUM_EXISTING_TESTCASES}+${NUM_OF_TESTCASES}
for (( i = $NUM_EXISTING_TESTCASES; i < ${MAX_NUM}; i++ )); do
	echo $i
	pqclean/bin/testvectors_${SCHEME}_clean|sed -n '1p;3p' > .testcase
	paste -d':' .prefix .testcase > "${DEST}/$(printf "%05d" $i)"
done

rm .prefix .testcase
