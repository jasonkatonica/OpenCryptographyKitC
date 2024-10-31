#!/bin/bash

make -k OPSYS=OSX_ARM64 CONFIG=clean
make -k OPSYS=OSX_ARM64 CONFIG=release create_all
export LD_LIBRARY_PATH=${{ github.workspace }}/OpenCryptographyKitC/openssl-1.1.1/
make -k OPSYS=OSX_ARM64 CONFIG=release all
make -k OPSYS=OSX_ARM64CONFIG=release iccpkg
make -k OPSYS=OSX_ARM64 CONFIG=release show_config
cd ..
cd iccpkg
make -k OPSYS=OSX_ARM64 CONFIG=release all