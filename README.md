# Secure Network Interface with SGX


This repo provides network security functionality within an Intel SGX enclave.
The [documentation](doc/main.md) provides a short overview of the functionality.
My [master thesis](thesis.pdf) contains technical details and background information.
_________________________________________________________________________
**Build Setup (Simulation Mode):**

> :warning: **Warning**: The build-instructions in this repo might be outdated. Please do not rely on those build-instructions and refer to official Intel-instructions instead. This has been only tested with Ubuntu 18.04.

Install the packages:    
`make cmake git g++ cppcheck`    
`ocaml ocamlbuild automake autoconf libtool wget python libssl-dev`    
    
Download, build and install the linux-sgx sdk:    
`git clone https://github.com/intel/linux-sgx.git`    
`cd linux-sgx`    
`./download_prebuilt.sh`    
`make sdk`    
`cd linux/installer/bin`    
`./build-installpkg.sh sdk`    
`./sgx_linux_x64_sdk_XXX.bin # install in "~" when asked`
    
Build and run the tests:

`./run_tests_locally.sh SIM`

_________________________________________________________________________
**Build Setup (Hardware Mode):**

Please complete the simulation mode instructions before setting up the hardware mode.
Hardware mode works only on SGX-supported platforms.

Configure your system to `SGX enabled`. You might need to enable SGX within your BIOS settings.

Build and install the SGX Driver according to the instructions in
`https://github.com/intel/linux-sgx-driver`.    
Afterwards, check whether the SGX Driver is running:
`lsmod | grep isgx`

Install the packages:    
`libprotobuf-dev protobuf-compiler libcurl4-openssl-dev`

Build and install the SGX Platform Service:   
`cd linux-sgx`   
`make`   
`cd linux/installer/bin`   
`./build-installpkg.sh psw`   
`sudo ./sgx_linux_x64_psw_XXX.bin`   

Build and run the tests:

`git clean -xfd # cleanup for a fresh build`    
`./run_tests_locally.sh HW`    


_________________________________________________________________________
**Future work:**

Implementing those protocol validations in C is a bad idea with respect to security.
The choice of the C Programming Language was only made because the Rust-SGX-support was still in its early stages at the time of writing.
Therefore, I strongly recommend that future TEE implementations use a secure language from the beginning (e.g. Rust, Go, Kotlin).

More generally, given todays knowledge and research advancements, the usage of C for security-critical systems is a huge mistake.
Unfortunately, this is the security-world that we have in 2020. Large systems like the Linux-kernel cannot be rewritten at once, but they need to be rewritten in a gradual manner.

Nevertheless, the usage of C can still be acceptable for *safety-critical* systems.
In this context, please be careful to correctly distinguish between security-critical systems (e.g. a parsing-library) and safety-critical systems (e.g. a flight control computer).



_________________________________________________________________________
**Limitations of SGX:**
Currently, SGX cannot directly access any external hardware.
Therefore, it is necessary to establish a cryptographic channel to securely communicate between an SGX enclave and external hardware.
In this work, we used a "MACSec gateway" for this cryptographic channel.
Other TEEs can be configured to avoid this issue altogether (e.g. ARM TrustZone).
