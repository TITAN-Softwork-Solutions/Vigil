use crate::engine::Engine;
use anyhow::{anyhow, Result};
use ferrisetw::{
    parser::Parser,
    provider::Provider,
    schema_locator::SchemaLocator,
    trace::stop_trace_by_name,
    trace::UserTrace,
    EventRecord,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

const TRACE_NAME: &str = "TITAN-Operative-CE";

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_FILE_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";

pub struct EtwSession {
    stop_flag: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = stop_trace_by_name(TRACE_NAME);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

pub fn start_etw(engine: Arc<Engine>) -> Result<EtwSession> {
    let _ = stop_trace_by_name(TRACE_NAME);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_thread = stop_flag.clone();

    let join = thread::Builder::new()
        .name("tml-etw-worker".to_string())
        .spawn(move || {
            for attempt in 0..2 {
                match run_trace(engine.clone(), stop_flag_thread.clone()) {
                    Ok(()) => break,
                    Err(e) => {
                        let msg = format!("{e:?}");
                        eprintln!("[TML][ETW] start failed (attempt {}): {}", attempt + 1, msg);

                        if msg.contains("AlreadyExist") && attempt == 0 {
                            let _ = stop_trace_by_name(TRACE_NAME);
                            thread::sleep(Duration::from_millis(150));
                            continue;
                        }
                        break;
                    }
                }
            }
        })?;

    Ok(EtwSession {
        stop_flag,
        join: Some(join),
    })
}

fn run_trace(engine: Arc<Engine>, stop_flag: Arc<AtomicBool>) -> Result<()> {
    let engine_proc = engine.clone();
    let process_cb = move |record: &EventRecord, schema_locator: &SchemaLocator| {
        let schema = match schema_locator.event_schema(record) {
            Ok(s) => s,
            Err(_) => return,
        };

        let parser = Parser::create(record, &schema);
        let pid = record.process_id();

        let image_name: String = match parser.try_parse("ImageName") {
            Ok(v) => v,
            Err(_) => return,
        };

        let cmdline: Option<String> = parser.try_parse("CommandLine").ok();
        engine_proc.on_process_start(pid, image_name, cmdline);
    };

    let engine_file = engine.clone();
    let file_cb = move |record: &EventRecord, schema_locator: &SchemaLocator| {
        let schema = match schema_locator.event_schema(record) {
            Ok(s) => s,
            Err(_) => return,
        };

        let parser = Parser::create(record, &schema);

        let event_id = record.event_id();
        if event_id != 12 && event_id != 0 && event_id != 65 && event_id != 66 {
            return;
        }

        let pid: u32 = record.process_id();

        let file_key: u64 = parser
            .try_parse("FileKey")
            .or_else(|_| parser.try_parse("FileObject"))
            .unwrap_or(0);

        let file_object: u64 = parser.try_parse("FileObject").unwrap_or(0);

        if event_id == 0 {
            if file_key == 0 {
                return;
            }

            let file_name: String = match parser.try_parse("FileName") {
                Ok(v) => v,
                Err(_) => return,
            };

            engine_file.on_file_name_mapping(file_key, file_name);
            return;
        }

        if event_id == 65 || event_id == 66 {
            if file_key != 0 {
                engine_file.clear_file_key(file_key);
            }
            return;
        }

        let target: Option<String> = parser.try_parse::<String>("FileName").ok().or_else(|| {
            if file_key != 0 {
                engine_file.resolve_file_key(file_key)
            } else {
                None
            }
        });

        let Some(target) = target else {
            return;
        };

        let Some((data_name, _)) = engine_file.match_protected_rule(&target) else {
            return;
        };

        let proc_path = engine_file.resolve_process_image(pid);

        if engine_file.is_pid_trusted(pid, &proc_path) {
            if file_object != 0 {
                engine_file.learn_whitelisted_file_object(file_object, pid);
            }
            return;
        }

        if file_object != 0 {
            if let Some(owners) = engine_file.whitelisted_file_object_owner(file_object) {
                if !owners.is_empty() {
                    engine_file.alert(
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

        engine_file.alert(
            pid,
            proc_path,
            target,
            data_name,
            event_id,
            "protected_resource_access",
            "untrusted process attempted access to protected resource",
        );
    };

    let process_provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .level(0x5)
        .any(u64::MAX)
        .add_callback(process_cb)
        .build();

    let file_provider = Provider::by_guid(KERNEL_FILE_GUID)
        .level(0x5)
        .any(u64::MAX)
        .add_callback(file_cb)
        .build();

    let _trace = UserTrace::new()
        .named(TRACE_NAME.to_string())
        .enable(process_provider)
        .enable(file_provider)
        .start_and_process()
        .map_err(|e| anyhow!("{e:?}"))?;

    while !stop_flag.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(250));
    }

    Ok(())
}