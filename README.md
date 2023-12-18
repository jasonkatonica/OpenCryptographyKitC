# OpenCryptographyKitC

The Open Cryptography Kit for C to which this document refers is based on the C language and is usable by products that are based on C or C++.

# Build for Linux 64

make -k -C icc OPSYS=AMD64_LINUX create_all
make -k -C icc OPSYS=AMD64_LINUX all

Other options include CONFIG=debug

# Build for Linux 32 bit

make -k -C icc OPSYS=LINUX create_all
make -k -C icc OPSYS=LINUX all

Other options as above

# Build for Windows 64

make -k -C icc OPSYS=WIN64_VS2022 create_all
make -k -C icc OPSYS=WIN64_VS2022 all

Other options as above

Note this build is not constrained to MS VS 2022 but is tested on that platform
