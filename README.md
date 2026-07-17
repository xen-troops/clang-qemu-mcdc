# MC/DC analysis tool

## Status

Tool supports only Aarch64 instruction set. The tool is tailored
mostly for Xen hypervisor.

The MC/DC tool is still in heavy R&D state. Expect bugs anywhere.

## Principle of Operation

When compiling C code without any optimisations, compiler generally
produces very predictable code. By employing techniques similar to
pattern matching, it is possible to identify processor instruction
that correspond to leaf boolean expressions (AKA Conditions in MC/DC
lingo) and put tracepoints to that instructions.

Next, QEMU plugin can collect trace date and another tool can be used
to produce MC/DC report.

## How to run

### Prerequisites

#### ARM Toolchain for Embedded v22.1.0
The tool was tested ARM Toolchain for Embedded (
https://github.com/arm/arm-toolchain/blob/arm-software/arm-software/embedded/README.md
). The toolchain should be installed and used for building software
under test.

#### LCOV tool 2.4+
MC/DC tool depends on LCOV for generating human-readable reports. As
LCOV supports MC/DC reports from version 2.4, user must ensure that
LCOV 2.4 (or newer) is installed.

#### QEMU 10.2+
MC/DC tool uses Qemu plugin for collect trace data. Plugin was tested
with QEMU 10.2

#### `bear` tool
MC/DC tool depends on `compile_commands.json` file to properly parse
source code. To generate this file, `bear` tool is used.

#### Checklist
 - [ ] ARM Toolchain for Embedded (ATfE) 22.1.0 installed
 - [ ] ARM Toolchain for Embedded (ATfE) 22.1.0 in `$PATH`
 - [ ] LCOV tool 2.4+ is installed
 - [ ] QEMU 10.2+ is installed
 - [ ] `bear` tool is installed

### Building QEMU plugin

The plugin is the part of this repo. It is located in `qemu-plugin` directory. Build it with `make` command:

```
# cd qemu-plugin
# make
```

### Fetching and building Xen

Xen shall be cloned from Xen-Troops repo, and branch
`4.22.0-rc4-mcdc-demo` shall be used:

```
# git clone https://github.com/xen-troops/xen.git -b 4.22.0-rc4-mcdc-demo
```

Change directory into `xen` inside newly cloned `xen` repo:

```
# cd xen/xen
```

All following commands shall be issues within this directory.

Check that ATfE clang is used:

```
# which clang
```

Load default config:

```
# make XEN_TARGET_ARCH=arm64  CROSS_COMPILE=aarch64-linux-gnu- arm64_defconfig
```

Additionally, enable the following options, either by editing `.config` or running `menucofig`:

```
CONFIG_EXPERT=y
CONFIG_NO_OPTIMIZE=y
CONFIG_FRAME_POINTER=y
CONFIG_DEBUG_INFO=y
```

Finally, build Xen while generating `compile_commands.json`:


```
# bear --append -- make XEN_TARGET_ARCH=arm64 clang=y llvm=y -j8 HOSTCC=gcc
```

### Running MC/DC tool analysis tool

First, we need to find all eligible boolean expressions in the codebase:

```
# python3 <path_to_mcdc_tool_repo>/mcdc_tool_parser.py xen.pickle compile_commands.json
```

This will take about a minute, depending on your machine.

Next step is to analyse `xen-syms` file to match boolean expressions
against binary code and create tracepoints:

```
# python3 <path_to_mcdc_tool_repo>/mcdc_tool_dwarf.py xen-syms xen.pickle xen-dwarf.pickle plugin.conf
```

This pass will take much more time. Depending our your CPU, expect
30-60 minutes.  (Performance will be optimized later). Luckily this
step needs to be done once per Xen build. After than you can run as
many data collection sessions as you want.

The last step will produce `plugin.conf` file which can be used by QEMU plugin.

### Running QEMU and collecting trace data

Run QEMU as usual, but add `-plugin <path_to_mcdc_tool_repo>/qemu-plugin/libbrtrace.so,config=plugin.conf`
option to enable QEMU plugin and data collection.

In our case, we'll run QEMU + Xen like that:

```
qemu-system-aarch64 -m 4G -smp 1 \
        -nographic \
        -kernel xen \
        -machine virt,acpi=off,secure=off,mte=off,virtualization=on,gic-version=max \
        -append "dom0_mem=1G loglvl=all guest_loglvl=all console=dtuart console_timestamps=boot" \
        -cpu cortex-a57 \
        -device guest-loader,addr=0x42000000,kernel=/home/lorc/work/linux/arch/arm64/boot/Image,bootargs="console=hvc0 earlyprintk=xen nokaslr root=/dev/vda rw" \
        -drive id=rootfs,file=/home/lorc/work/arch-arm/aarch64-arch.img,if=none,format=raw -device virtio-blk-pci,drive=rootfs \
		-plugin ~/work/mcdc/qemu-plugin/libbrtrace.so,config=plugin.conf
```

This is the place where test suite can be executed.

Each invocation with QEMU plugin will produce `brtrace.dat` file. This
file contains tracing information for that run.

### Analysing trace data

Use `mcdc_coverage_gen.py` script to generate report in LCOV format:

```
# python3 <path_to_mcdc_tool_repo>/mcdc_coverage_gen.py --dwarf xen-dwarf.pickle --lcov xen-coverage.info brtrace.dat
```

This will generate ``xen-covegate.info` file that can be feed to LCOV:

```
# genhtml --branch-coverage --mcdc-coverage -o qemu-coverage-report xen-coverage.info
```

This will create `qemu-coverage-report` directory with human-readable
report. Use your browser to open `qemu-coverage-report/index.html` or just call `xdg-open`:

```
# xdg-open qemu-coverage-report/index.html
```


