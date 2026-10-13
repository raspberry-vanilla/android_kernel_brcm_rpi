// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2026 Google LLC.

use crate::{content::DmaBufContent, wrap::Wrap};

use kernel::{bindings, device, prelude::*, types::ARef, uaccess::UserSlice, uapi};

#[pin_data]
pub(crate) struct WrapFdDevice {
    wrapping_dev: ARef<device::Device>,
    wrap: Option<Pin<KBox<Wrap>>>,
}

#[vtable]
impl kernel::miscdevice::MiscDevice for WrapFdDevice {
    type Ptr = Pin<KBox<Self>>;

    fn open(
        _file: &kernel::fs::File,
        misc: &kernel::miscdevice::MiscDeviceRegistration<Self>,
    ) -> Result<Pin<KBox<Self>>> {
        let wrapping_dev = kernel::types::ARef::from(misc.device());

        KBox::try_pin_init(
            try_pin_init! {
                WrapFdDevice { wrapping_dev, wrap: None }
            },
            GFP_KERNEL,
        )
    }

    fn ioctl(_me: Pin<&Self>, _file: &kernel::fs::File, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            uapi::WRAPFD_DEV_IOC_WRAP => {
                use kernel::ioctl::_IOC_SIZE;
                let user_slice = UserSlice::new(UserPtr::from_addr(arg), _IOC_SIZE(cmd));
                let wrap_args = user_slice.reader().read::<uapi::wrapfd_wrap>()?;

                // SAFETY: The Linux kernel's `get_close_on_exec` safely handles arbitrary `fd`
                // values (including invalid ones) by looking up the descriptor table under RCU
                // lock without causing undefined behavior.
                let close_on_exec = unsafe { bindings::get_close_on_exec(wrap_args.fd) };

                let wrap: Pin<KBox<Wrap>> = KBox::pin_init(Wrap::new(close_on_exec), GFP_KERNEL)?;

                Ok(Self::wrap_file(wrap, &wrap_args)? as isize)
            }
            _ => Err(ENOTTY),
        }
    }
}

impl WrapFdDevice {
    fn wrap_file(wrap: Pin<KBox<Wrap>>, args: &uapi::wrapfd_wrap) -> Result<u32> {
        if (args.prot & !(bindings::PROT_READ | bindings::PROT_WRITE)) != 0 {
            return Err(EINVAL);
        }

        if args.reserved != 0 {
            return Err(EINVAL);
        }

        let close_on_exec = wrap.close_on_exec;

        let content = DmaBufContent::new(args.fd, args.prot)?;
        Self::publish_wrap(wrap, content, close_on_exec).map_err(|(err, _content)| err)
    }

    pub(crate) fn publish_wrap(
        dev: Pin<KBox<Wrap>>,
        content: DmaBufContent,
        close_on_exec: bool,
    ) -> Result<u32, (Error, DmaBufContent)> {
        DmaBufContent::create_wrap(dev, content, close_on_exec)
    }
}
