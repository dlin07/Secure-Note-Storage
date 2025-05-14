# Secure-Note-Storage
This project develops a Trusted Application (TA) that securely stores, retrieves, and deletes confidential notes within the Trusted Execution Environment (TEE) using OP-TEE. The application will ensure that sensitive information remains protected from unauthorized access in the normal world.

### Prerequisites
Make sure to follow the installation process for OP-TEE QEMU. Below are some instructions to make sure your system is ready to run the program.
**Note: Requires Ubuntu 20.04, 22.04, or 24.04** 

## Installation and Run Steps

### 1. Installing OP-TEE in Simulation Mode
1. Open the terminal and install the following tools to build OP-TEE:
```shell
$ apt update && apt upgrade -y
$ apt install -y \
 adb \
 acpica-tools \
 autoconf \
 automake \
 bc \
 bison \
 build-essential \
 ccache \
 cpio \
 cscope \
 curl \
 device-tree-compiler \
 e2tools \
 expect \
 fastboot \
 flex \
 ftp-upload \
 gdisk \
 git \
 libattr1-dev \
 libcap-ng-dev \
 libfdt-dev \
 libftdi-dev \
 libglib2.0-dev \
 libgmp3-dev \
 libhidapi-dev \
 libmpc-dev \
 libncurses5-dev \
 libpixman-1-dev \
 libslirp-dev \
 libssl-dev \
 libtool \
 libusb-1.0-0-dev \
 make \
 mtools \
 netcat \
 ninja-build \
 python3-cryptography \
 python3-pip \
 python3-pyelftools \
 python3-serial \
 python-is-python3 \
 rsync \
 swig \
 unzip \
 uuid-dev \
 wget \
 xalan \
 xdg-utils \
 xterm \
 xz-utils \
 zlib1g-dev
```

2. Create a repository named `optee-qemu` in any directory of your preference, and install the repository using `repo init` and `repo sync`:
```shell
$ mkdir optee-qemu
$ cd optee-qemu
$ repo init -u https://github.com/OP-TEE/manifest.git
$ repo sync
```

3. Now, the repository should be set up to run OP-TEE in simulation mode with a few other commands, but we will first clone this repository into the `optee-qemu` directory first.

### 2. Cloning This Repository
1. Navigate from the home directory of `optee-qemu` into the following path `optee-qemu/optee_examples/secure_note_storage`.
2. Clone the repository through any conventional means: HTTPS, SSH, or GitHub CLI

### 3. Running the Trusted Application
1. Navigate into the following directory inside of `optee-qemu`:
```shell
# Assuming you are in the optee-qemu directory
$ cd build
```

2. Run the following commands to set up the tools for OP-TEE QEMU and run OP-TEE. After, two UART consoles should appear on the screen: one for the normal world and another for the secure world. **This step might take a few minutes.**
```shell
$ make toolchains -j2
$ make run
```

3. Note that this step may take a few minutes. To speed up the process, use the command `make -j32 run` (but may not show all error messages). If the make run command does not work, check that your `$PATH` environment variable does not contain spaces or other invalid characters, or try using `sudo make run`.

4. Now, once the two consoles appear and the QEMU console is waiting for input, continue by entering the following command into the QEMU console (the main terminal):
```
(qemu) c
```

5. In the normal world console, type in `root` or `test`, to login, then use the following command to run the Trusted Application:
```
# optee_example_secure_note_storage
```

# Credits and Acknowledgements
The instructions to set up the OP-TEE QEMU environment in simulation mode come from the [official documentation for OP-TEE](https://optee.readthedocs.io/en/latest/index.html) and from [Jeremy Hui](https://github.com/jeremywhui).
