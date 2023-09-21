#!/bin/bash

cd Enclave_1
make clean && make SGX_MODE=SIM
cd ..

cd Enclave_2
make clean && make SGX_MODE=SIM
cd ..
