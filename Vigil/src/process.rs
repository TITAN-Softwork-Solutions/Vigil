use anyhow::Result;
use std::mem::size_of;

use windows::{
    core::PWSTR,
    Win32::{
        Foundation::CloseHandle,
        System::{
            ProcessStatus::EnumProcesses,
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
};

pub fn enum_process_ids() -> Result<Vec<u32>> {
    let mut cap = 4096usize;
    loop {
        let mut buf = vec![0u32; cap];
        let mut bytes_returned: u32 = 0;

        unsafe {
            if EnumProcesses(
                buf.as_mut_ptr(),
                (buf.len() * size_of::<u32>()) as u32,
                &mut bytes_returned,
            )
            .is_err()
            {
                anyhow::bail!("EnumProcesses failed");
            }
        }

        let count = (bytes_returned as usize) / size_of::<u32>();
        if bytes_returned as usize >= buf.len() * size_of::<u32>() {
            cap = cap.saturating_mul(2);
            continue;
        }

        buf.truncate(count);
        return Ok(buf);
    }
}

pub fn get_process_image_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return Some("SYSTEM".to_string());
    }

    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

        let mut buf: Vec<u16> = vec![0u16; 4096];
        let mut size: u32 = buf.len() as u32;

        let ok = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok();

        let _ = CloseHandle(h);

        if !ok || size == 0 {
            return None;
        }

        buf.truncate(size as usize);
        Some(String::from_utf16_lossy(&buf))
    }
}
