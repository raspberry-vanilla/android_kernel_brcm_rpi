// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

#![allow(missing_docs)]

mod content;
mod io_context;
mod wrap;
mod wrapfd_device;

use crate::wrapfd_device::WrapFdDevice;
use kernel::{prelude::*, InPlaceModule};

module! {
    type: WrapFdModule,
    name: "wrapfd",
    authors: ["Andreas Huber"],
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

#[pin_data]
struct WrapFdModule {
    #[pin]
    miscdev: kernel::miscdevice::MiscDeviceRegistration<WrapFdDevice>,
}

impl InPlaceModule for WrapFdModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        let options = kernel::miscdevice::MiscDeviceOptions {
            name: kernel::c_str!("wrapfd"),
        };

        try_pin_init!(Self {
            miscdev <- kernel::miscdevice::MiscDeviceRegistration::register(options),
        })
    }
}
