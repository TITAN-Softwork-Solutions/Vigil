use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    os::windows::io::AsRawHandle,
};

const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004

#[repr(C)]
#[derive(Clone, Copy)]
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    Object: *mut c_void,
    UniqueProcessId: usize,
    HandleValue: usize,
    GrantedAccess: u32,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u16,
    HandleAttributes: u32,
    Reserved: u32,
}

#[repr(C)]
struct SYSTEM_HANDLE_INFORMATION_EX {
    NumberOfHandles: usize,
    Reserved: usize,
    Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 1],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut c_void,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

fn status_ok(status: i32) -> bool {
    status >= 0
}

fn query_system_handles() -> Result<Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>> {
    let mut buf_size: usize = 8 * 1024 * 1024;
    let mut buf: Vec<u8> = vec![0u8; buf_size];
    let mut needed: u32 = 0;

    loop {
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut needed as *mut u32,
            )
        };

        if status_ok(status) {
            break;
        }

        if status == STATUS_INFO_LENGTH_MISMATCH {
            buf_size = (needed as usize).max(buf_size * 2);
            buf.resize(buf_size, 0u8);
            continue;
        }

        anyhow::bail!("NtQuerySystemInformation failed");
    }

    let mut entries = Vec::new();
    unsafe {
        let info = buf.as_ptr() as *const SYSTEM_HANDLE_INFORMATION_EX;
        let count = (*info).NumberOfHandles;
        let base = &(*info).Handles as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

        entries.reserve(count);
        for i in 0..count {
            entries.push(*base.add(i));
        }
    }

    Ok(entries)
}

pub fn collect_file_objects_for_pids(trusted_pids: &[u32]) -> Result<HashMap<u64, HashSet<u32>>> {
    let trusted_set: HashSet<u32> = trusted_pids.iter().copied().collect();

    let exe = std::env::current_exe().ok();
    let file_probe = exe.and_then(|path| std::fs::File::open(path).ok());
    let handle_val = file_probe.as_ref().map(|f| f.as_raw_handle() as usize);
    let pid = std::process::id() as usize;

    let entries = match query_system_handles() {
        Ok(entries) => entries,
        Err(_) => return Ok(HashMap::new()),
    };

    let Some(handle_val) = handle_val else {
        return Ok(HashMap::new());
    };

    let Some(file_type_index) = entries
        .iter()
        .find(|e| e.UniqueProcessId == pid && e.HandleValue == handle_val)
        .map(|e| e.ObjectTypeIndex)
    else {
        return Ok(HashMap::new());
    };

    let mut out: HashMap<u64, HashSet<u32>> = HashMap::new();

    for e in entries {
        if e.ObjectTypeIndex != file_type_index {
            continue;
        }

        let pid = e.UniqueProcessId as u32;
        if !trusted_set.contains(&pid) {
            continue;
        }

        // Kernel object pointer
        let obj = e.Object as u64;
        if obj == 0 {
            continue;
        }

        out.entry(obj).or_default().insert(pid);
    }

    Ok(out)
}
