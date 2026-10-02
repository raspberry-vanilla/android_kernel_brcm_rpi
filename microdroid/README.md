# Microdroid  Directory Tree

This directory contains KMI for the Microdroid kernel - a smaller kernel (with
it's dedicated microdroid_defconfig) used in the Microdroid (protected) virtual
machines.

Directory structure mimics the one under gki/:

```none
microdroid
|-- README.md
|-- aarch64
|   |-- symbols
|   |   |-- base
|   |   |-- $partner
|   |   +-- ...
|   |-- abi.stg
|   |-- abi.stg.allowed_breaks
+-- ...
```

The `microdroid` directory has one subdirectory per
[Kleaf](https://android.googlesource.com/kernel/build/+/refs/heads/main/kleaf/README.md)
architecture. Within each such subdirectory:

* `symbols` - contains symbol list files
   * `base` - a short list of symbols that are essential for ABI safety
   * `$partner` - a symbol list file for a specific partner
      * maintained by the partner
      * e.g. `kmi_symbol_list = "//common:microdroid/aarch64/symbols/acme"`
      * e.g. `tools/bazel run //modules:acme_aarch64_microdroid_abi_update_symbol_list`
* `abi.stg` - the tracked ABI
   * maintained by Kleaf
   * e.g. `tools/bazel run //common:kernel_aarch64__microdroid_abi_update`
* `abi.stg.allowed_breaks` - a list of allowed ABI differences
   * for use by Gerrit ABI monitoring
* `afdo` - [AutoFDO profile for building kernel for the architecture](aarch64/afdo/README.md)
