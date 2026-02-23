use std::os::windows::prelude::OsStrExt;

/// Convert &str to null-terminated wide string for Win32 APIs.
pub fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}
