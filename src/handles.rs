use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
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

/// FAST: no DuplicateHandle, no GetFinalPathNameByHandleW.
/// Just build: FileObjectPtr -> {pid,...} for trusted processes.
/// This is enough to detect handle-duping later when ETW gives FileObject.
pub fn collect_file_objects_for_pids(trusted_pids: &[u32]) -> Result<HashMap<u64, HashSet<u32>>> {
    let trusted_set: HashSet<u32> = trusted_pids.iter().copied().collect();

    // NtQuerySystemInformation needs a dynamic buffer
    let mut buf_size: usize = 8 * 1024 * 1024; // start 8MB
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

        // fail closed
        return Ok(HashMap::new());
    }

    let mut out: HashMap<u64, HashSet<u32>> = HashMap::new();

    unsafe {
        let info = buf.as_ptr() as *const SYSTEM_HANDLE_INFORMATION_EX;
        let count = (*info).NumberOfHandles;
        let base = &(*info).Handles as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

        for i in 0..count {
            let e = *base.add(i);

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
    }

    Ok(out)
}
