#!/bin/bash
make PLATFORM=nucleo-f207zg -j16 ${1} && ./scripts/flash.sh ${1} && python3 streaming/test.py -n 1 ${1}
