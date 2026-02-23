use anyhow::Result;
use std::mem::size_of;

use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError},
        System::{
            ProcessStatus::EnumProcesses,
            Threading::{
                OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW,
            },
        },
    },
    core::PWSTR,
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
        let mut cap = 512usize;
        loop {
            let mut buf: Vec<u16> = vec![0u16; cap];
            let mut size: u32 = buf.len() as u32;

            let ok = QueryFullProcessImageNameW(
                h,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
            .is_ok();

            if ok && size > 0 {
                let _ = CloseHandle(h);
                buf.truncate(size as usize);
                return Some(String::from_utf16_lossy(&buf));
            }

            let last = GetLastError();
            if last == ERROR_INSUFFICIENT_BUFFER && cap < 32 * 1024 {
                cap = cap.saturating_mul(2);
                continue;
            }

            let _ = CloseHandle(h);
            return None;
        }
    }
}
