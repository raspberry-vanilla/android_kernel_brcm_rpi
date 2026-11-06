// SPDX-License-Identifier: GPL-2.0

//! Device Tree / Open Firmware abstractions.
//!
//! C headers: [`include/linux/of.h`](srctree/include/linux/of.h),
//! [`include/linux/of_reserved_mem.h`](srctree/include/linux/of_reserved_mem.h)

use crate::{
    bindings,
    device::Device,
    device_id::{RawDeviceId, RawDeviceIdIndex},
    error::to_result,
    io::{
        PhysAddr,
        ResourceSize, //
    },
    prelude::*,
};

/// IdTable type for OF drivers.
pub type IdTable<T> = &'static dyn kernel::device_id::IdTable<DeviceId, T>;

/// An open firmware device id.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct DeviceId(bindings::of_device_id);

// SAFETY: `DeviceId` is a `#[repr(transparent)]` wrapper of `struct of_device_id` and
// does not add additional invariants, so it's safe to transmute to `RawType`.
unsafe impl RawDeviceId for DeviceId {
    type RawType = bindings::of_device_id;
}

// SAFETY: `DRIVER_DATA_OFFSET` is the offset to the `data` field.
unsafe impl RawDeviceIdIndex for DeviceId {
    const DRIVER_DATA_OFFSET: usize = core::mem::offset_of!(bindings::of_device_id, data);

    fn index(&self) -> usize {
        self.0.data as usize
    }
}

impl DeviceId {
    /// Create a new device id from an OF 'compatible' string.
    pub const fn new(compatible: &'static CStr) -> Self {
        let src = compatible.to_bytes_with_nul();
        // Replace with `bindings::of_device_id::default()` once stabilized for `const`.
        // SAFETY: FFI type is valid to be zero-initialized.
        let mut of: bindings::of_device_id = unsafe { core::mem::zeroed() };

        // TODO: Use `copy_from_slice` once stabilized for `const`.
        let mut i = 0;
        while i < src.len() {
            of.compatible[i] = src[i];
            i += 1;
        }

        Self(of)
    }
}

/// Create an OF `IdTable` with an "alias" for modpost.
#[macro_export]
macro_rules! of_device_table {
    ($table_name:ident, $module_table_name:ident, $id_info_type: ty, $table_data: expr) => {
        const $table_name: $crate::device_id::IdArray<
            $crate::of::DeviceId,
            $id_info_type,
            { $table_data.len() },
        > = $crate::device_id::IdArray::new($table_data);

        $crate::module_device_table!("of", $module_table_name, $table_name);
    };
}

/// A Device Tree `/reserved-memory` region resolved from a device's `memory-region` property.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReservedMemRegion {
    start: PhysAddr,
    size: ResourceSize,
}

impl ReservedMemRegion {
    /// Returns the base physical address of the reserved memory region.
    #[inline]
    pub const fn start(&self) -> PhysAddr {
        self.start
    }

    /// Returns the size in bytes of the reserved memory region.
    #[inline]
    pub const fn size(&self) -> ResourceSize {
        self.size
    }
}

/// Resolves the Device Tree `memory-region` entry at `index` for `dev`.
///
/// Wraps the C
/// [`of_reserved_mem_region_to_resource()`](srctree/include/linux/of_reserved_mem.h) function.
#[inline]
pub fn reserved_mem_region(dev: &Device, index: u32) -> Result<ReservedMemRegion> {
    let mut res = bindings::resource::default();

    // SAFETY: By the type invariant of `Device`, `dev.as_raw()` is a valid `struct device` whose
    // `of_node` is null or valid for the lifetime of `dev`, and `&mut res` is a valid out-pointer
    // initialized by `of_reserved_mem_region_to_resource` on success.
    let size = unsafe {
        to_result(bindings::of_reserved_mem_region_to_resource(
            (*dev.as_raw()).of_node,
            index,
            &mut res,
        ))?;
        bindings::resource_size(&mut res)
    };

    Ok(ReservedMemRegion {
        start: res.start,
        size,
    })
}
