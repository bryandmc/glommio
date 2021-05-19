//!
//! IP networking stack functionality

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

impl fmt::Display for IpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpVersion::V4 => f.write_str("4"),
            IpVersion::V6 => f.write_str("6"),
        }
    }
}
