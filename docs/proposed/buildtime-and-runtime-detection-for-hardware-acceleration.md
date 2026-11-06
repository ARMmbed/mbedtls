# Build-time and runtime detection for hardware acceleration with advance CPU features

## Introduction
This document discusses how to support the algorithms that can do hardware acceleration with advance CPU features.

NOTE: Pure-software is special accelerator and called `built-in` in this document

## Requirements

### Stories

There are some issues about hardware accelerators in MbedTLS:
- Tri-state choice for configuration is not enough for modern CPU.
- Conflict between SHA512 and AES with crypto extension in Arm64.
- Build fail on Arm64 host.
- Duplicate CPU feature detection code for algorithm.
- Test coverage is not enough.

And some general issues:
- Configuration options are too complex. If possible, do not add new option.
- Code size optimization is important.

#### Multiple choices for accelerators

As [#5378](https://github.com/Mbed-TLS/mbedtls/issues/5387#issuecomment-1373523124) mention, hardware acceleration has tri-state choice:
1. H/W acceleration not used
1. H/W acceleration used if detected at runtime
1. H/W acceleration (only) used (will fail if H/W support not present).

State 2 needs a function to detect CPU feature sets which is called `runtime detection` in this document.
For state 1 and 3, `runtime detection` function is not a MUST option. Due to code size optimization, the `runtime detection` code should be disabled at compile time and compiler options should be set at command line.

An algorithm can be accelerated by different CPU feature sets. For example, AES can be accelerated by AES or VAES in x64 or by crypto or SVEAES in arm64.

So, the accelerators should be disabled/enabled by multiple choices.

To reduce the complex of configuration options, `runtime detection` should not be a configuration option, it should be a helper macro. If both accelerators are enabled, `runtime detection` should be enabled. And it should be disabled by default.

Open question: Should we disable/enable `runtime detection` for each algorithm?

#### Build and test fail for Arm64

Two issues are reported at [Build on Arm64 HOST Fail](https://github.com/Mbed-TLS/mbedtls/issues/5758).
- Build fail when `MBEDTLS_SHA{256,512}_USE_A64_*` enabled and build on Arm64 host. `-march=armv8.2-a+sha3` or `-march=armv8-a+crypto` is required for this case.
- AESCE module reports `illegal instrucion` error when `MBEDTLS_SHA512_USE_A64_*` and `MBEDTLS_AESCE_C` are enabled together. Unexpected `eor3` instruction is generated in AESCE module. The instruction belongs to sha3 extension.

> - [#6932](https://github.com/Mbed-TLS/mbedtls/pull/6932) provides a cheap solution for the issues.
> - [#6895](https://github.com/Mbed-TLS/mbedtls/pull/6895) provides AESCE module.

Open question: [#6932](https://github.com/Mbed-TLS/mbedtls/pull/6932) implements it with `pragma` and [#7078](https://github.com/Mbed-TLS/mbedtls/pull/7078) implements it with attribute, which one is better?

#### Hardware accelerators summary

4 hardware accelerations in `development` and 1 in [#6895](https://github.com/Mbed-TLS/mbedtls/pull/6895)
- SHA256 with Arm64 crypto extension
- SHA512 with Arm64 sha3 extension
- AES/GCM with x86_64 aes extension
- AES/GCM with x86 padlock extension
- AES/GCM with Arm64 crypto extension

All of the accelerators implement their own `runtime detection`. 3 functions are enough for time being.

Beside that, Arm32 accelerators are not implemented.

Below are the list of exists runtime detection functions.
> - `mbedtls_a64_crypto_sha256_determine_support`
> - `mbedtls_a64_crypto_sha512_determine_support`
> - `mbedtls_padlock_has_support`
> - `mbedtls_aesni_has_support`
> - `mbedtls_aesce_has_support`

#### Runtime detection problems

- For x86/x64, `cpuid` instruction is available for it. It is not a big problems.
- For Arm64/32, it depenes on operation system. CPU feature sets registers can not access from userspace. OSs provide the information. For this case, we should provide built-in detection and alternative detection function for unkown OS

[Open Question]: Which OSs should be supported in runtime detection? linux, macos, windows, bare-metal? Which OSs should be in the guarantee list?

#### Test coverage

Unfortunately, the test coverage for acceleration is not enough.
- No Arm64 test components ( exists componets only guarantee build pass ).
- No tests guarantee accelerators or pure-software code work correctly, both x86/arm have same issue.
  - Whether the accelerated code is executed depends on the host CPU type for x86. For timebeing, pure-software code is never executed in test.

> - Arm64 HOST test is added at [#6895](https://github.com/Mbed-TLS/mbedtls/pull/6895)

- We should design new test components to make sure acceleration functions are called and return correctly result.
- To test runtime detection module, we should build and test with different compilers and targets.
- Platform independent code(pure-software) should be covered also.

### Summary

- Add multiple choices for accelerators, and take pure-software implementation as special accelerators.
- Add runtime detection module for each architecture.
- Improve test coverages, guarantee accelerators are called and work correctly
- Provid alternative way for runtime detection.
- If possible, provide way to get best optimization.

## Suggestions

### Build-time detection


- Introduce architecture helper macros `MBEDTLS_ARCH_IS_{X86,X64,ARM64,ARM32}`. That is enabled base on compiler target information.

Also some code should be replaced.

| | new name |
|---|---|
|MBEDTLS_HAVE_X86_64|MBEDTLS_ARCH_IS_X64|
|MBEDTLS_HAVE_X86|MBEDTLS_ARCH_IS_X86|
|MBEDTLS_HAVE_ARM64|MBEDTLS_ARCH_IS_ARM64|

Eg.
```c
/* include/mbedtls/runtime.h */
#if !defined(MBEDTLS_ARCH_IS_X86) && defined(__i386__)
#define MBEDTLS_ARCH_IS_X86
#endif
....
```

- Acceleration modules should be disabled on unsupported target architecture. Internal macros `MBEDTLS_<ALGO>_HAVE_<ACCELERATOR>` are used for enable/disable module.

Eg.
```c
/* library/runtime_internal.h */
#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_AESCE_C) && defined(MBEDTLS_ARCH_IS_ARM64)
#define MBEDTLS_AES_HAVE_AESCE 1
#else
#define MBEDTLS_AES_HAVE_AESCE 0
#endif
#endif

/* library/aesce.c */
#if MBEDTLS_AES_HAVE_AESCE
...
#endif
```

> Open question: Should we create script to enable/disable modules base on the compiler command line ? If user knows the target CPU type, he/she can set `-mcpu=xxx` and pass that to the scripts, the script can enable/disable module options base on the flags.

- `MBEDTLS_RUNTIME_C` and `MBEDTLS_ARCH_IS_{X86,X64,ARM64,ARM32}` are introduced as internal toggle of runtime detection module. `MBEDTLS_RUNTIME_C` MUST be enabled when two or more accelerations of any algorithm on target platform are enabled.
  - For the algorithm, `MBEDTLS_<ALGO>_ACCELERATOR_NUM` is introduced for counting the number of accelerators. If it is one, runtime detection should be disabled for the algorithm to reduce code size.

### Runtime detection

This setcion describe the structure of runtime detection.
#### Public Header File

This section defines which functions and consts should be available for user.


- `MBEDTLS_CPU_HAS_FEATURES_ALT` is introduced for external detection function. If it is defined, built-in runtime detection module will be disabled.

We publish funtion `mbedtls_cpu_has_features_<arch>` and available values in `include/mbedtls/runtime.h`. That MUST return a boolean value(true for feature sets available). External detection function MUST follow same definition.

Bellow are definition for `mbedtls_cpu_has_features_arm64` and `mbedtls_cpu_has_features_x64`
- x86/x64, well defined instruction `cpuid` is available, just followup it and add const values for them.
  - Prototype: `bool mbedtls_cpu_has_features_x64(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx)`
  - Const values should be followup document of `cpuid`
- Arm32/Arm64, we should followup [linux elf hwcaps](https://github.com/torvalds/linux/blob/master/Documentation/arm64/elf_hwcaps.rst) and reference the const value from
[`asm/hwcap.h`](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/hwcap.h)
  - Prototype: `bool mbedtls_cpu_has_features_arm64(unsigned long hwcap, unsigned long hwcap2);`

> I am not familliar with x86. Please correct me.
>
> - Can i386 share `mbedtls_cpu_has_features_x64` ?
> - Should we put A32 mode of Armv8 into list? How about armv7?

```
#### Runtime detection module for x86/x86_64

This module provides runtime detection functions for x86/x86_64.

TODO

#### Runtime detection module for Arm64

This module provides runtime detection functions for arm64/arm32.

> Armv8 has some runtime states, A32/T32/A64. For time being, we only consider about A64.

The feature sets bit masks will followup [asm/hwcap.h from linux kernel](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/hwcap.h)

- Linux: followup [elf_hwcaps](https://github.com/torvalds/linux/blob/master/Documentation/arm64/elf_hwcaps.rst)
- If CPUID registers can be accessed, read registers for the feature sets.
- Windows: [`IsProcessorFeaturePresent`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent). We should map the result to ELF hwcaps.
- Apple: [`sysctlbyname`](https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_instruction_set_characteristics) and map the results to ELF hwcaps
- If `signal` and `setjmp` available, implement it with `SIG_ILL`.
- Other cases, user should provide `MBEDTLS_CPU_HAS_FEATURES_ALT`.


### Acceleration and Algorithm modules

- Each acceleration MUST be put into seperate module and expose needed feature sets to algorithm modules.
- Pure-software implementation is a special acceleration and `MBEDTLS_<ALGO>_HAS_NO_BUILTIN` is introduced to disable it.
- If no accelerator available, the algorithm interface returns `MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED`
- For the Acceleration modules, it should be wrapped with file scope cpu modifier.
  - For clang/gcc, it is pair of `#pragma`
  - For MSVC, TODO

> Open question: Clang/GCC can overwrite target options with function attribute. Should we use that? It looks better than `#pragma`

### Tests

#### i386/x86_64

We can emulator the CPU with `qemu-user -cpu` on linux and pickup the CPU with/without feature we used.
- x86_64 AES-NI
- i386 VIA padlock

> TODO: figure out which CPU does not support above features.
> Should we remove VIA padlock here ?

#### Arm64

For a basic tests, Travis CI and Amazon provide Arm64 instances. Just enable it.

To test if accelerators work correctly, we should think about OSs one by one.
- Linux: emulator with `qemu-user -cpu`.
- Windows, freebsd, baremetal: emulator with `qemu-system-aarch64 -cpu`
  - It needs more workloads and can be implemented in local machine.
> Should we test with `qemu-system-aarch64 -cpu`? For Windows and Macos, we can not emulate all cases without it.

For runtime detection, there are 3 differents method, We can add test options to cover them.

- default test, with elf hwcap
- With `SIG_ILL`, this needs a new config option for test purpose.
- With system regs, this needs a new config option for test purpose.


> There are 3 accelerators that depends on `crypto extension` and `sha3 extension`. And `crypto extension` can not be disabled by offical `qemu`. So, we can not test without `crypto extension` case. I have a qemu patch for disable `crypto extension`, is it worth to add it? The patch is rejected by qemu community.

## Furture more

TODO
