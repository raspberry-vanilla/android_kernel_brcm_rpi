// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

#![allow(missing_docs)]

mod content;
mod io_context;
mod wrap;
mod wrapfd_device;

use crate::wrapfd_device::WrapFdDevice;
use kernel::{prelude::*, Module};

module! {
    type: RealWrapFdModule,
    name: "wrapfd",
    author: "Andreas Huber",
    description: "WrapFD",
    license: "GPL",
    imports_ns: ["DMA_BUF"],
    params: {
        max_nr_load_reqs: usize {
            default: 32,
            description: "",
        },
        min_bytes_per_req: usize {
            default: 0x100000,  // 1MB
            description: "",
        },
    },
}

#[allow(dead_code)]
struct RealWrapFdModule(Pin<KBox<WrapFdModule>>);

impl Module for RealWrapFdModule {
    fn init(module: &'static kernel::ThisModule) -> Result<Self> {
        let inner = KBox::try_pin_init(WrapFdModule::init(module), GFP_KERNEL)?;
        Ok(Self(inner))
    }
}

#[pin_data]
struct WrapFdModule {
    #[pin]
    miscdev: kernel::miscdevice::MiscDeviceRegistration<WrapFdDevice>,
}

impl WrapFdModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        let options = kernel::miscdevice::MiscDeviceOptions {
            name: kernel::c_str!("wrapfd"),
        };

        try_pin_init!(Self {
            miscdev <- kernel::miscdevice::MiscDeviceRegistration::register(
                options,
                Ok(WrapFdDevice),
            ),
        })
    }
}
