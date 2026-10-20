// SPDX-License-Identifier: GPL-2.0

//! The `kernel` prelude.
//!
//! These are the most common items used by Rust code in the kernel,
//! intended to be imported by all Rust code, for convenience.
//!
//! # Examples
//!
//! ```
//! use kernel::prelude::*;
//! ```

#[doc(no_inline)]
pub use core::pin::Pin;

pub use crate::alloc::{flags::*, Box, KBox, KVBox, KVVec, KVec, VBox, VVec, Vec};

#[doc(no_inline)]
pub use macros::{module, pin_data, pinned_drop, vtable, Zeroable};

pub use super::build_assert;

// `super::std_vendor` is hidden, which makes the macro inline for some reason.
#[doc(no_inline)]
pub use super::dbg;
pub use super::{
    pr_alert, pr_alert_ratelimited, pr_crit, pr_crit_ratelimited, pr_debug, pr_debug_ratelimited,
    pr_emerg, pr_emerg_ratelimited, pr_err, pr_err_ratelimited, pr_info, pr_info_ratelimited,
    pr_notice, pr_notice_ratelimited, pr_warn, pr_warn_ratelimited,
};

pub use super::{init, pin_init, try_init, try_pin_init};

pub use super::static_assert;

pub use super::error::{code::*, Error, Result};

pub use super::{str::CStr, ThisModule};

pub use super::init::{InPlaceInit, InPlaceWrite, Init, PinInit};

pub use super::current;
