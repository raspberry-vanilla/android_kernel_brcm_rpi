// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

use crate::{content::DmaBufContent, wrap::Wrap};

use kernel::{bindings, device, prelude::*, types::ARef, uaccess::UserSlice, uapi};

pub(crate) struct WrapFdDevice;

#[pin_data]
pub(crate) struct WrapfdDevFile {
    wrapping_dev: ARef<device::Device>,
    wrap: Option<Pin<KBox<Wrap>>>,
}

#[vtable]
impl kernel::miscdevice::MiscDevice for WrapFdDevice {
    type File = Pin<KBox<WrapfdDevFile>>;

    fn open(
        _file: &kernel::fs::File,
        misc: &kernel::miscdevice::MiscDeviceRegistration<Self>,
    ) -> Result<Self::File> {
        let wrapping_dev = kernel::types::ARef::from(misc.device());

        KBox::try_pin_init(
            try_pin_init! {
                WrapfdDevFile { wrapping_dev, wrap: None }
            },
            GFP_KERNEL,
        )
    }

    fn ioctl(
        _me: Pin<&WrapfdDevFile>,
        _file: &kernel::fs::File,
        cmd: u32,
        arg: usize,
    ) -> Result<isize> {
        match cmd {
            uapi::WRAPFD_DEV_IOC_WRAP => {
                use kernel::ioctl::_IOC_SIZE;
                let user_slice = UserSlice::new(arg, _IOC_SIZE(cmd));
                let wrap_args = user_slice.reader().read::<uapi::wrapfd_wrap>()?;

                Ok(Self::wrap_file(&wrap_args)? as isize)
            }
            _ => Err(ENOTTY),
        }
    }
}

impl WrapFdDevice {
    fn wrap_file(args: &uapi::wrapfd_wrap) -> Result<u32> {
        if (args.prot & !(bindings::PROT_READ | bindings::PROT_WRITE)) != 0 {
            return Err(EINVAL);
        }

        if args.reserved != 0 {
            return Err(EINVAL);
        }

        let content = DmaBufContent::new(args.fd, args.prot)?;

        // SAFETY: `args.fd` is a valid file descriptor, otherwise `DmaBufContent::new` would have
        // failed.
        let close_on_exec = unsafe { bindings::get_close_on_exec(args.fd) };

        let wrap: Pin<KBox<Wrap>> = KBox::pin_init(Wrap::new(close_on_exec), GFP_KERNEL)?;

        DmaBufContent::publish_wrap(wrap, content, close_on_exec, false)
            .map_err(|(err, _content)| err)
    }
}
