// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DMA-buf subsystem abstractions.

pub mod buf;

pub use buf::{CpuAccess, DmaBuf, DmaBufAttachment, DmaBufMapping, DmaBufVmap};
