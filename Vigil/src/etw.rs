use crate::engine::Engine;
use anyhow::{anyhow, Result};
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    sync::Arc,
    thread,
    time::Duration,
};
use windows::{
    core::{GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_SUCCESS,
            ERROR_WMI_INSTANCE_NOT_FOUND,
        },
        System::Diagnostics::Etw::{
            CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW,
            ProcessTrace, StartTraceW, TdhGetProperty, TdhGetPropertySize,
            CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
            EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
            EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE,
            PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP, PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR, TRACE_LEVEL_VERBOSE,
            WNODE_FLAG_TRACED_GUID,
        },
    },
};

const TRACE_NAME: &str = "TITAN-Vigil";

const KERNEL_PROCESS_GUID: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const KERNEL_FILE_GUID: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);

const INVALID_TRACE_HANDLE: u64 = u64::MAX;

struct CallbackCtx {
    engine: Arc<Engine>,
}

pub struct EtwSession {
    trace_name: Vec<u16>,
    control_handle: CONTROLTRACE_HANDLE,
    trace_handle: PROCESSTRACE_HANDLE,
    join: Option<std::thread::JoinHandle<()>>,
    _ctx: Box<CallbackCtx>,
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        let _ = stop_trace_by_name(&self.trace_name);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

pub fn start_etw(engine: Arc<Engine>) -> Result<EtwSession> {
    for attempt in 0..2 {
        match start_trace(engine.clone()) {
            Ok(session) => return Ok(session),
            Err(e) => {
                let msg = format!("{e:?}");
                eprintln!("[ETW] start failed (attempt {}): {}", attempt + 1, msg);
                if msg.contains("already exists") && attempt == 0 {
                    let _ = stop_trace_by_name(&to_wide(TRACE_NAME));
                    thread::sleep(Duration::from_millis(150));
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(anyhow!("failed to start ETW session"))
}

fn start_trace(engine: Arc<Engine>) -> Result<EtwSession> {
    let trace_name = to_wide(TRACE_NAME);
    let (_props_buf, props_ptr) = build_properties(&trace_name);

    let mut control_handle = CONTROLTRACE_HANDLE::default();
    let status =
        unsafe { StartTraceW(&mut control_handle, PCWSTR(trace_name.as_ptr()), props_ptr) };
    if status != ERROR_SUCCESS {
        if status == ERROR_ALREADY_EXISTS {
            return Err(anyhow!("ETW session already exists"));
        }
        if status == ERROR_ACCESS_DENIED {
            return Err(anyhow!("StartTraceW failed: access denied (run as administrator)"));
        }
        return Err(anyhow!("StartTraceW failed: {}", status.0));
    }

    if let Err(e) = enable_provider(control_handle, &KERNEL_PROCESS_GUID) {
        let _ = stop_trace_by_name(&trace_name);
        return Err(e);
    }
    if let Err(e) = enable_provider(control_handle, &KERNEL_FILE_GUID) {
        let _ = stop_trace_by_name(&trace_name);
        return Err(e);
    }

    let ctx = Box::new(CallbackCtx { engine });
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
    logfile.LoggerName = PWSTR(trace_name.as_ptr() as *mut _);
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD
        | PROCESS_TRACE_MODE_REAL_TIME
        | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.Context = (&*ctx as *const CallbackCtx) as *mut c_void;
    unsafe {
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
    }

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == INVALID_TRACE_HANDLE {
        let _ = stop_trace_by_name(&trace_name);
        let last = unsafe { GetLastError() };
        return Err(anyhow!("OpenTraceW failed: {}", last.0));
    }

    let trace_handle_thread = trace_handle;
    let join = thread::Builder::new()
        .name("vigil-etw-process".to_string())
        .spawn(move || {
            let status = unsafe { ProcessTrace(&[trace_handle_thread], None, None) };
            if status != ERROR_SUCCESS {
                eprintln!("[ETW] ProcessTrace failed: {}", status.0);
            }
            let _ = unsafe { CloseTrace(trace_handle_thread) };
        })?;

    Ok(EtwSession {
        trace_name,
        control_handle,
        trace_handle,
        join: Some(join),
        _ctx: ctx,
    })
}

fn enable_provider(handle: CONTROLTRACE_HANDLE, guid: &GUID) -> Result<()> {
    let status = unsafe {
        EnableTraceEx2(
            handle,
            guid as *const GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_VERBOSE as u8,
            u64::MAX,
            0,
            0,
            None,
        )
    };

    if status != ERROR_SUCCESS {
        if status == ERROR_ACCESS_DENIED {
            return Err(anyhow!("EnableTraceEx2 failed: access denied (run as administrator)"));
        }
        return Err(anyhow!("EnableTraceEx2 failed: {}", status.0));
    }

    Ok(())
}

fn stop_trace_by_name(trace_name: &[u16]) -> Result<()> {
    let (_props_buf, props_ptr) = build_properties(trace_name);
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(trace_name.as_ptr()),
            props_ptr,
            EVENT_TRACE_CONTROL_STOP,
        )
    };

    if status == ERROR_SUCCESS || status == ERROR_WMI_INSTANCE_NOT_FOUND {
        Ok(())
    } else {
        Err(anyhow!("ControlTraceW failed: {}", status.0))
    }
}

fn build_properties(trace_name: &[u16]) -> (Vec<u8>, *mut EVENT_TRACE_PROPERTIES) {
    let name_bytes = trace_name.len() * size_of::<u16>();
    let total_size = size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes;
    let mut buf = vec![0u8; total_size];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

    unsafe {
        (*props).Wnode.BufferSize = total_size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let name_dst = buf.as_mut_ptr().add(size_of::<EVENT_TRACE_PROPERTIES>()) as *mut u16;
        std::ptr::copy_nonoverlapping(trace_name.as_ptr(), name_dst, trace_name.len());
    }

    (buf, props)
}

fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }

    let ctx = unsafe { (*record).UserContext as *const CallbackCtx };
    if ctx.is_null() {
        return;
    }

    let engine = unsafe { &(*ctx).engine };
    let provider = unsafe { (*record).EventHeader.ProviderId };
    let event_id = unsafe { (*record).EventHeader.EventDescriptor.Id };
    let pid = unsafe { (*record).EventHeader.ProcessId };

    if provider == KERNEL_PROCESS_GUID {
        let image_name = match get_property_string(record, "ImageName") {
            Some(v) => v,
            None => return,
        };
        let cmdline = get_property_string(record, "CommandLine");
        engine.on_process_start(pid, image_name, cmdline);
        return;
    }

    if provider != KERNEL_FILE_GUID {
        return;
    }

    if event_id != 12 && event_id != 0 && event_id != 65 && event_id != 66 {
        return;
    }

    let file_key = get_property_u64(record, "FileKey")
        .or_else(|| get_property_u64(record, "FileObject"))
        .unwrap_or(0);

    let file_object = get_property_u64(record, "FileObject").unwrap_or(0);

    if event_id == 0 {
        if file_key == 0 {
            return;
        }

        let file_name = match get_property_string(record, "FileName") {
            Some(v) => v,
            None => return,
        };

        engine.on_file_name_mapping(file_key, file_name);
        return;
    }

    if event_id == 65 || event_id == 66 {
        if file_key != 0 {
            engine.clear_file_key(file_key);
        }
        return;
    }

    let target = get_property_string(record, "FileName").or_else(|| {
        if file_key != 0 {
            engine.resolve_file_key(file_key)
        } else {
            None
        }
    });

    let Some(target) = target else {
        return;
    };

    let Some((data_name, _)) = engine.match_protected_rule(&target) else {
        return;
    };

    let proc_path = engine.resolve_process_image(pid);

    if engine.is_pid_trusted(pid, &proc_path) {
        if file_object != 0 {
            engine.learn_whitelisted_file_object(file_object, pid);
        }
        return;
    }

    if file_object != 0 {
        if let Some(owners) = engine.whitelisted_file_object_owner(file_object) {
            if !owners.is_empty() {
                engine.alert(
                    pid,
                    proc_path,
                    target,
                    data_name,
                    event_id,
                    "suspicious_whitelisted_handle_access",
                    "untrusted process touched protected resource via whitelisted file object",
                );
                return;
            }
        }
    }

    engine.alert(
        pid,
        proc_path,
        target,
        data_name,
        event_id,
        "protected_resource_access",
        "untrusted process attempted access to protected resource",
    );
}

fn get_property_bytes(record: *mut EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let wide = to_wide(name);
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wide.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };

    let mut size: u32 = 0;
    let status = unsafe { TdhGetPropertySize(record, None, &[desc], &mut size as *mut u32) };
    if status != ERROR_SUCCESS.0 || size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let status = unsafe { TdhGetProperty(record, None, &[desc], &mut buf) };
    if status != ERROR_SUCCESS.0 {
        return None;
    }

    Some(buf)
}

fn get_property_string(record: *mut EVENT_RECORD, name: &str) -> Option<String> {
    let buf = get_property_bytes(record, name)?;

    if buf.len() >= 2 && buf.len() % 2 == 0 {
        let mut u16s: Vec<u16> = buf
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        if let Some(pos) = u16s.iter().position(|&c| c == 0) {
            u16s.truncate(pos);
        }
        if !u16s.is_empty() {
            return Some(String::from_utf16_lossy(&u16s));
        }
    }

    let s = String::from_utf8_lossy(&buf)
        .trim_end_matches('\0')
        .to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn get_property_u64(record: *mut EVENT_RECORD, name: &str) -> Option<u64> {
    let buf = get_property_bytes(record, name)?;
    match buf.len() {
        8 => Some(u64::from_le_bytes(buf.try_into().ok()?)),
        4 => Some(u32::from_le_bytes(buf.try_into().ok()?) as u64),
        2 => Some(u16::from_le_bytes(buf.try_into().ok()?) as u64),
        1 => Some(buf[0] as u64),
        _ => {
            if buf.len() >= 8 {
                Some(u64::from_le_bytes(buf[..8].try_into().ok()?))
            } else {
                None
            }
        }
    }
}
