mod buttons;
mod icon;

use std::{fmt, fmt::Debug};

pub use buttons::Buttons;
pub use icon::Icon;
use zerocopy::{FromBytes, I32, Immutable, KnownLayout, LE};

/// * <https://github.com/NSIS-Dev/nsis/blob/v311/Source/Platform.h#L563>
/// * <https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-messagebox>
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, FromBytes, Immutable, KnownLayout,
)]
#[repr(transparent)]
pub struct MessageBoxFlags(I32<LE>);

impl MessageBoxFlags {
    const BUTTONS_MASK: i32 = 0xF;
    const ICON_MASK: i32 = 0xF0;
    const DEFAULT_BUTTON_MASK: i32 = 0xF00;

    /// Creates a new [`MessageBoxFlags`].
    #[inline]
    const fn new(mb_flags: i32) -> Self {
        Self(I32::new(mb_flags))
    }

    /// Returns the inner flags.
    #[inline]
    const fn flags(self) -> i32 {
        self.0.get()
    }

    /// Returns the buttons flags.
    #[inline]
    pub(super) const fn buttons_flags(self) -> i32 {
        self.flags() & Self::BUTTONS_MASK
    }

    /// Returns the icon flags.
    #[inline]
    pub(super) const fn icon_flags(self) -> i32 {
        self.flags() & Self::ICON_MASK
    }

    /// Returns the default button flags.
    #[inline]
    pub(super) const fn default_button_flags(self) -> i32 {
        self.flags() & Self::DEFAULT_BUTTON_MASK
    }

    /// Returns the button flags as a [`Buttons`].
    #[inline]
    pub const fn buttons(self) -> Buttons {
        Buttons::new(self)
    }

    /// Returns the icon flags as a [`Icon`].
    #[inline]
    pub const fn icon(self) -> Option<Icon> {
        Icon::new(self)
    }

    /// Returns the configured silent response or the visible default button.
    pub fn default_response(self, silent: bool) -> Option<i32> {
        let silent_response = (self.flags() as u32 >> 21) as i32;
        if silent && silent_response != 0 {
            return Some(silent_response);
        }
        let buttons: &[i32] = match self.buttons_flags() {
            0 => &[1],
            1 => &[1, 2],
            2 => &[3, 4, 5],
            3 => &[6, 7, 2],
            4 => &[6, 7],
            5 => &[4, 2],
            6 => &[2, 10, 11],
            _ => return None,
        };
        buttons
            .get((self.default_button_flags() >> 8) as usize)
            .copied()
    }
}

impl fmt::Display for MessageBoxFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.buttons())?;
        if let Some(icon) = self.icon() {
            write!(f, " | {icon}")?;
        }
        Ok(())
    }
}

impl From<I32<LE>> for MessageBoxFlags {
    #[inline]
    fn from(flags: I32<LE>) -> Self {
        Self(flags)
    }
}

impl From<i32> for MessageBoxFlags {
    #[inline]
    fn from(flags: i32) -> Self {
        Self::new(flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_buttons_and_silent_overrides_are_distinct() {
        assert_eq!(MessageBoxFlags::from(4).default_response(false), Some(6));
        assert_eq!(
            MessageBoxFlags::from(4 | 0x100).default_response(false),
            Some(7)
        );
        assert_eq!(
            MessageBoxFlags::from(3 | 0x200).default_response(false),
            Some(2)
        );
        let flags = MessageBoxFlags::from(4 | (7 << 21));
        assert_eq!(flags.default_response(false), Some(6));
        assert_eq!(flags.default_response(true), Some(7));
        assert_eq!(
            MessageBoxFlags::from(4 | 0x300).default_response(false),
            None
        );
    }
}
