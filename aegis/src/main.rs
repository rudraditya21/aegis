#![forbid(unsafe_code)]

use aegis_core::{
    Action, ApplicationType, BackpressureMode, BehaviorAlert, BehaviorKind, Cidr, Direction,
    FailMode, FirewallCounters, FirewallManager, FlowSnapshot, FlowStats, PacketMetadata,
    PolicyCondition, PolicyEntry, PortRange, Rule, RuleSubject, SignatureEngine, TimeWindow,
    TlsMetadata, parse_cidr, validate_policies, validate_rules,
};
use packet_parser::{IpProtocol, ParseError};
use dataplane::{
    BackendKind, Dataplane, DataplaneConfig, DataplaneHandle, FrameView,
    RssConfig,
};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::Instant;
use utils::{
    config_root, enforce_writable, hex_to_bytes, hex_to_bytes_or_exit, resolve_config_path,
};
mod runtime_config;
use runtime_config::load_runtime_config;
mod packet_ref;
use packet_ref::{FrameRef, PacketRef};
mod rss;
use rss::FlowSharder;

#[derive(Debug, Clone)]
struct Tuning {
    flow_capacity: usize,
    flow_shards: Option<usize>,
    reassembly_buffer: usize,
    signature_tail_budget: usize,
    backpressure_mode: BackpressureMode,
    fail_mode: Option<FailMode>,
    dpi_scratch_budget: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            flow_capacity: 65_535,
            flow_shards: None,
            reassembly_buffer: 4096,
            signature_tail_budget: 64 * 1024,
            backpressure_mode: BackpressureMode::Drop,
            fail_mode: None,
            dpi_scratch_budget: 256 * 1024,
        }
    }
}

#[derive(Debug)]
struct WorkerSummary {
    counters: FirewallCounters,
    flow_stats: FlowStats,
    flows: Vec<FlowSnapshot>,
    alerts: Vec<BehaviorAlert>,
    suspicious: Vec<FlowSnapshot>,
    rule_hits: HashMap<u64, u64>,
    proto_counters: HashMap<IpProtocol, u64>,
}

#[derive(Debug)]
struct CaptureSummary {
    processed: usize,
    counters: FirewallCounters,
    flow_stats: FlowStats,
    flows: Vec<FlowSnapshot>,
    alerts: Vec<BehaviorAlert>,
    suspicious: Vec<FlowSnapshot>,
    rule_hits: HashMap<u64, u64>,
    proto_counters: HashMap<IpProtocol, u64>,
}

#[derive(Debug)]
enum ShardPlan {
    Single,
    PerQueue { queues: Vec<u16> },
    Software { workers: usize },
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage_and_exit();
        return;
    };

    let result = match cmd.as_str() {
        "add-rule" => cmd_add_rule(args.collect()),
        "remove-rule" => cmd_remove_rule(args.collect()),
        "list-rules" => cmd_list_rules(args.collect()),
        "add-policy" => cmd_add_policy(args.collect()),
        "remove-policy" => cmd_remove_policy(args.collect()),
        "list-policies" => cmd_list_policies(args.collect()),
        "eval" => cmd_eval(args.collect()),
        "eval-batch" => cmd_eval_batch(args.collect()),
        "capture" => cmd_capture(args.collect()),
        "failover" => cmd_failover(args.collect()),
        "metrics" => cmd_metrics(args.collect()),
        "set-flow-capacity" => cmd_set_flow_capacity(args.collect()),
        "audit-status" => cmd_audit_status(),
        "show-config-root" => {
            println!("{}", config_root().display());
            Ok(())
        }
        "capture-async" => cmd_capture_async(args.collect()),
        "replay" => cmd_replay(args.collect()),
        "dataplane-diag" => cmd_dataplane_diag(args.collect()),
        _ => Err(format!("Unknown command: {}", cmd)),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_add_rule(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut rule_line: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--rule" => rule_line = iter.next().cloned(),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = rules_path.ok_or("Missing --rules <file>")?;
    let rules_path = resolve_config_path(&rules_path, true)?;
    let rule_line = rule_line.ok_or("Missing --rule \"<rule line>\"")?;
    // Validate rule
    let _ = parse_rule_line(&rule_line).map_err(|e| format!("Invalid rule: {e}"))?;
    append_rule_line(&rules_path, &rule_line)?;
    println!("Added rule to {}", rules_path.display());
    Ok(())
}

fn cmd_add_policy(args: Vec<String>) -> Result<(), String> {
    let mut path: Option<String> = None;
    let mut line: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--policies" => path = iter.next().cloned(),
            "--rule" => line = iter.next().cloned(),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let path = path.ok_or("Missing --policies <file>")?;
    let path = resolve_config_path(&path, true)?;
    let line = line.ok_or("Missing --rule \"<policy line>\"")?;
    parse_policy_line(&line)?; // validate
    append_rule_line(&path, &line)?;
    println!("Added policy rule to {}", path.display());
    Ok(())
}

fn cmd_remove_policy(args: Vec<String>) -> Result<(), String> {
    let mut path: Option<String> = None;
    let mut id: Option<usize> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--policies" => path = iter.next().cloned(),
            "--id" => {
                id = iter
                    .next()
                    .map(|s| s.parse::<usize>().map_err(|_| "invalid id".to_string()))
                    .transpose()?
            }
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let path = path.ok_or("Missing --policies <file>")?;
    let path = resolve_config_path(&path, true)?;
    let id = id.ok_or("Missing --id <number>")?;
    remove_rule_line(&path, id)?;
    println!("Removed policy {}", id);
    Ok(())
}

fn cmd_list_policies(args: Vec<String>) -> Result<(), String> {
    let mut path: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--policies" => path = iter.next().cloned(),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let path = path.ok_or("Missing --policies <file>")?;
    let path = resolve_config_path(&path, false)?;
    let lines = read_rule_lines(&path)?;
    for (idx, line) in lines.iter().enumerate() {
        println!("{}: {}", idx + 1, line);
    }
    Ok(())
}

fn cmd_remove_rule(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut id: Option<usize> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--id" => {
                id = iter
                    .next()
                    .map(|s| s.parse::<usize>().map_err(|_| "invalid id".to_string()))
                    .transpose()?
            }
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = rules_path.ok_or("Missing --rules <file>")?;
    let rules_path = resolve_config_path(&rules_path, true)?;
    let id = id.ok_or("Missing --id <number>")?;
    remove_rule_line(&rules_path, id)?;
    println!("Removed rule {}", id);
    Ok(())
}

fn cmd_list_rules(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = rules_path.ok_or("Missing --rules <file>")?;
    let rules_path = resolve_config_path(&rules_path, false)?;
    let lines = read_rule_lines(&rules_path)?;
    for (idx, line) in lines.iter().enumerate() {
        println!("{}: {}", idx + 1, line);
    }
    Ok(())
}

fn cmd_eval(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut policies_path: Option<String> = None;
    let mut hex: Option<String> = None;
    let mut direction: Option<Direction> = None;
    let mut iface: Option<String> = None;
    let mut disable_ifaces: Vec<String> = Vec::new();
    let mut disable_logs = false;
    let mut disable_ids = false;
    let mut disable_ips = false;
    let mut disable_geo = false;
    let mut disable_time = false;
    let mut audit_log: Option<String> = None;
    let mut tuning = Tuning::default();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--policies" => policies_path = iter.next().cloned(),
            "--hex" => hex = iter.next().cloned(),
            "--direction" => {
                direction = iter
                    .next()
                    .map(|d| parse_direction(d))
                    .transpose()
                    .map_err(|e| format!("{e}"))?
            }
            "--iface" => iface = iter.next().cloned(),
            "--disable-iface" => {
                if let Some(n) = iter.next() {
                    disable_ifaces.push(n.clone());
                }
            }
            "--no-logs" => disable_logs = true,
            "--disable-ids" => disable_ids = true,
            "--disable-ips" => disable_ips = true,
            "--disable-geo" => disable_geo = true,
            "--disable-time" => disable_time = true,
            "--audit-log" => audit_log = iter.next().cloned(),
            "--flow-capacity" => {
                if let Some(v) = iter.next() {
                    tuning.flow_capacity = v.parse().map_err(|_| "invalid flow capacity")?;
                }
            }
            "--flow-shards" => {
                if let Some(v) = iter.next() {
                    tuning.flow_shards = Some(v.parse().map_err(|_| "invalid flow shards")?);
                }
            }
            "--reassembly-buffer" => {
                if let Some(v) = iter.next() {
                    tuning.reassembly_buffer = v.parse().map_err(|_| "invalid reassembly buffer")?;
                }
            }
            "--signature-tail-budget" => {
                if let Some(v) = iter.next() {
                    tuning.signature_tail_budget =
                        v.parse().map_err(|_| "invalid signature tail budget")?;
                }
            }
            "--dpi-scratch-budget" => {
                if let Some(v) = iter.next() {
                    tuning.dpi_scratch_budget =
                        v.parse().map_err(|_| "invalid dpi scratch budget")?;
                }
            }
            "--backpressure" => {
                if let Some(v) = iter.next() {
                    tuning.backpressure_mode = parse_backpressure(v)?;
                }
            }
            "--fail-open" => tuning.fail_mode = Some(FailMode::FailOpen),
            "--fail-closed" => tuning.fail_mode = Some(FailMode::FailClosed),
            other => return Err(format!("Unknown flag {other}")),
        }
    }

    let rules_path = rules_path.ok_or("Missing --rules <file>")?;
    let rules_path = resolve_config_path(&rules_path, false)?;
    let hex = hex.ok_or("Missing --hex <bytes>")?;
    let direction = direction.ok_or("Missing --direction <ingress|egress>")?;
    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let mut mgr = load_manager(&rules_path, policies_path.as_deref(), &tuning)?;
    if disable_logs {
        mgr.set_logging_enabled(false);
    }
    if disable_ids {
        mgr.set_ids_enabled(false);
    }
    if disable_ips {
        mgr.set_ips_enabled(false);
    }
    if disable_geo {
        mgr.set_geo_rules_enabled(false);
    }
    if disable_time {
        mgr.set_time_rules_enabled(false);
    }
    for name in disable_ifaces {
        mgr.disable_interface(&name);
    }
    let bytes = hex_to_bytes_or_exit(&hex);
    let capture_payload = capture_payload_enabled(&mgr);
    let meta = packet_metadata(&bytes, direction, capture_payload).map_err(|e| format!("{e:?}"))?;
    let eval = mgr.evaluate(&meta, iface.as_deref(), Instant::now());
    println!(
        "Action: {:?} (blocked_by_protector={})",
        eval.action, eval.blocked_by_protector
    );
    println!(
        "Flow state: {:?} (new={}) app={:?} tls_decrypt_ok={}",
        eval.flow.state, eval.flow.is_new, eval.flow.application, eval.tls_decryption_allowed
    );
    println!(
        "Counters: allowed={} dropped={}",
        mgr.counters().allowed,
        mgr.counters().dropped
    );
    println!("Flow table size: {}", mgr.flows().len());
    println!("Protocol counters: {:?}", mgr.protocol_counters());
    for snap in mgr.flows() {
        let sni = snap.tls.as_ref().and_then(|t| t.sni.clone());
        println!(
            "Flow {:?}:{:?} -> {:?}:{:?} proto={:?} state={:?} app={:?} tls_decrypt_ok={} tls_sni={:?}",
            snap.key.src_ip,
            snap.key.src_port,
            snap.key.dst_ip,
            snap.key.dst_port,
            snap.key.protocol,
            snap.state,
            snap.application,
            mgr.tls_decryption_allowed(),
            sni
        );
    }
    if let Some(path) = audit_log {
        write_audit(&path, &meta, &eval)?;
        println!("Audit log appended to {}", path);
    }
    if !mgr.alerts(None).is_empty() {
        println!("Alerts:");
        for alert in mgr.alerts(Some(50)) {
            println!(
                "- {:?} src={} dst={:?} port={:?} count={} at {:?}",
                alert.kind, alert.src, alert.dst, alert.port, alert.count, alert.timestamp
            );
        }
    }
    let susp = mgr.suspicious_flows();
    if !susp.is_empty() {
        println!("Suspicious flows:");
        for snap in susp {
            println!(
                "- {:?}:{:?} -> {:?}:{:?} state={:?} app={:?}",
                snap.key.src_ip,
                snap.key.src_port,
                snap.key.dst_ip,
                snap.key.dst_port,
                snap.state,
                snap.application
            );
        }
    }
    let rule_hits = mgr.rule_hits();
    if !rule_hits.is_empty() {
        println!("Rule hit counters: {:?}", rule_hits);
    }
    Ok(())
}

fn cmd_eval_batch(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut policies_path: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut direction: Option<Direction> = None;
    let mut disable_ids = false;
    let mut disable_ips = false;
    let mut disable_geo = false;
    let mut disable_time = false;
    let mut disable_logs = true;
    let mut tuning = Tuning::default();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--policies" => policies_path = iter.next().cloned(),
            "--file" => file_path = iter.next().cloned(),
            "--direction" => {
                direction = iter
                    .next()
                    .map(|d| parse_direction(d))
                    .transpose()
                    .map_err(|e| format!("{e}"))?
            }
            "--disable-ids" => disable_ids = true,
            "--disable-ips" => disable_ips = true,
            "--disable-geo" => disable_geo = true,
            "--disable-time" => disable_time = true,
            "--no-logs" => disable_logs = true,
            "--flow-capacity" => {
                if let Some(v) = iter.next() {
                    tuning.flow_capacity = v.parse().map_err(|_| "invalid flow capacity")?;
                }
            }
            "--flow-shards" => {
                if let Some(v) = iter.next() {
                    tuning.flow_shards = Some(v.parse().map_err(|_| "invalid flow shards")?);
                }
            }
            "--reassembly-buffer" => {
                if let Some(v) = iter.next() {
                    tuning.reassembly_buffer = v.parse().map_err(|_| "invalid reassembly buffer")?;
                }
            }
            "--signature-tail-budget" => {
                if let Some(v) = iter.next() {
                    tuning.signature_tail_budget =
                        v.parse().map_err(|_| "invalid signature tail budget")?;
                }
            }
            "--dpi-scratch-budget" => {
                if let Some(v) = iter.next() {
                    tuning.dpi_scratch_budget =
                        v.parse().map_err(|_| "invalid dpi scratch budget")?;
                }
            }
            "--backpressure" => {
                if let Some(v) = iter.next() {
                    tuning.backpressure_mode = parse_backpressure(v)?;
                }
            }
            "--fail-open" => tuning.fail_mode = Some(FailMode::FailOpen),
            "--fail-closed" => tuning.fail_mode = Some(FailMode::FailClosed),
            other => return Err(format!("Unknown flag {other}")),
        }
    }

    let rules_path = resolve_config_path(&rules_path.ok_or("Missing --rules <file>")?, false)?;
    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let file_path = file_path.ok_or("Missing --file <hex_lines>")?;
    let direction = direction.ok_or("Missing --direction <ingress|egress>")?;
    let lines = read_rule_lines(&rules_path)?;
    let policy_lines = if let Some(p) = &policies_path {
        read_rule_lines(p)?
    } else {
        Vec::new()
    };

    let file = File::open(&file_path).map_err(|e| format!("open file: {e}"))?;
    let reader = BufReader::new(file);
    let hex_packets: Vec<String> = reader
        .lines()
        .filter_map(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .collect();

    if hex_packets.is_empty() {
        return Err("no packets to process".into());
    }

    let results: Vec<Result<(aegis_core::Evaluation, PacketMetadata), String>> = hex_packets
        .par_iter()
        .map(|line| {
            let mut mgr = load_manager_from_lines(&lines, &policy_lines, &tuning)?;
            if disable_logs {
                mgr.set_logging_enabled(false);
            }
            if disable_ids {
                mgr.set_ids_enabled(false);
            }
            if disable_ips {
                mgr.set_ips_enabled(false);
            }
            if disable_geo {
                mgr.set_geo_rules_enabled(false);
            }
            if disable_time {
                mgr.set_time_rules_enabled(false);
            }
            let capture_payload = capture_payload_enabled(&mgr);
            let bytes = hex_to_bytes(line)?;
            let meta =
                packet_metadata(&bytes, direction, capture_payload).map_err(|e| format!("{e:?}"))?;
            let eval = mgr.evaluate(&meta, None, Instant::now());
            Ok((eval, meta))
        })
        .collect();

    let mut allowed = 0usize;
    let mut dropped = 0usize;
    for r in results {
        match r {
            Ok((eval, _)) => match eval.action {
                Action::Allow | Action::Redirect { .. } => allowed += 1,
                Action::Deny => dropped += 1,
            },
            Err(e) => {
                eprintln!("error: {e}");
            }
        }
    }
    println!(
        "Batch done: total={} allowed={} dropped={}",
        allowed + dropped,
        allowed,
        dropped
    );
    Ok(())
}

fn cmd_capture(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut policies_path: Option<String> = None;
    let mut iface: Option<String> = None;
    let mut count: usize = 10;
    let mut disable_logs = false;
    let mut disable_ids = false;
    let mut disable_ips = false;
    let mut disable_geo = false;
    let mut disable_time = false;
    let mut audit_log: Option<String> = None;
    let mut tuning = Tuning::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--policies" => policies_path = iter.next().cloned(),
            "--iface" => iface = iter.next().cloned(),
            "--count" => {
                if let Some(c) = iter.next() {
                    count = c.parse().map_err(|_| "invalid count".to_string())?;
                }
            }
            "--no-logs" => disable_logs = true,
            "--disable-ids" => disable_ids = true,
            "--disable-ips" => disable_ips = true,
            "--disable-geo" => disable_geo = true,
            "--disable-time" => disable_time = true,
            "--audit-log" => audit_log = iter.next().cloned(),
            "--flow-capacity" => {
                if let Some(v) = iter.next() {
                    tuning.flow_capacity = v.parse().map_err(|_| "invalid flow capacity")?;
                }
            }
            "--flow-shards" => {
                if let Some(v) = iter.next() {
                    tuning.flow_shards = Some(v.parse().map_err(|_| "invalid flow shards")?);
                }
            }
            "--reassembly-buffer" => {
                if let Some(v) = iter.next() {
                    tuning.reassembly_buffer = v.parse().map_err(|_| "invalid reassembly buffer")?;
                }
            }
            "--signature-tail-budget" => {
                if let Some(v) = iter.next() {
                    tuning.signature_tail_budget =
                        v.parse().map_err(|_| "invalid signature tail budget")?;
                }
            }
            "--dpi-scratch-budget" => {
                if let Some(v) = iter.next() {
                    tuning.dpi_scratch_budget =
                        v.parse().map_err(|_| "invalid dpi scratch budget")?;
                }
            }
            "--backpressure" => {
                if let Some(v) = iter.next() {
                    tuning.backpressure_mode = parse_backpressure(v)?;
                }
            }
            "--fail-open" => tuning.fail_mode = Some(FailMode::FailOpen),
            "--fail-closed" => tuning.fail_mode = Some(FailMode::FailClosed),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = rules_path.ok_or("Missing --rules <file>")?;
    let rules_path = resolve_config_path(&rules_path, false)?;
    let iface = iface.ok_or("Missing --iface <name>")?;

    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let runtime = load_runtime_config(&config_root())?;
    let dp_cfg = runtime.dataplane;
    let summary = run_capture_pipeline(
        iface.as_str(),
        &rules_path,
        policies_path.as_deref(),
        &tuning,
        dp_cfg,
        count,
        audit_log.as_deref(),
        disable_logs,
        disable_ids,
        disable_ips,
        disable_geo,
        disable_time,
    )?;
    println!(
        "Capture finished: processed={} allowed={} dropped={}",
        summary.processed,
        summary.counters.allowed,
        summary.counters.dropped
    );
    println!(
        "Flow stats: packets={} new_flows={} evicted={}",
        summary.flow_stats.packets,
        summary.flow_stats.new_flows,
        summary.flow_stats.evicted
    );
    println!("Protocol counters: {:?}", summary.proto_counters);
    for snap in summary.flows {
        println!(
            "Flow {:?}:{:?} -> {:?}:{:?} proto={:?} state={:?}",
            snap.key.src_ip,
            snap.key.src_port,
            snap.key.dst_ip,
            snap.key.dst_port,
            snap.key.protocol,
            snap.state
        );
    }
    if !summary.alerts.is_empty() {
        println!("Alerts:");
        for alert in summary.alerts.into_iter().take(100) {
            println!(
                "- {:?} src={} dst={:?} port={:?} count={} at {:?}",
                alert.kind, alert.src, alert.dst, alert.port, alert.count, alert.timestamp
            );
        }
    }
    let susp = summary.suspicious;
    if !susp.is_empty() {
        println!("Suspicious flows:");
        for snap in susp {
            println!(
                "- {:?}:{:?} -> {:?}:{:?} state={:?} app={:?}",
                snap.key.src_ip,
                snap.key.src_port,
                snap.key.dst_ip,
                snap.key.dst_port,
                snap.state,
                snap.application
            );
        }
    }
    let rule_hits = summary.rule_hits;
    if !rule_hits.is_empty() {
        println!("Rule hit counters: {:?}", rule_hits);
    }
    Ok(())
}

fn cmd_capture_async(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut policies_path: Option<String> = None;
    let mut iface: Option<String> = None;
    let mut count: usize = 10;
    let mut disable_logs = false;
    let mut disable_ids = false;
    let mut disable_ips = false;
    let mut disable_geo = false;
    let mut disable_time = false;
    let mut audit_log: Option<String> = None;
    let mut tuning = Tuning::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--policies" => policies_path = iter.next().cloned(),
            "--iface" => iface = iter.next().cloned(),
            "--count" => {
                if let Some(c) = iter.next() {
                    count = c.parse().map_err(|_| "invalid count".to_string())?;
                }
            }
            "--no-logs" => disable_logs = true,
            "--disable-ids" => disable_ids = true,
            "--disable-ips" => disable_ips = true,
            "--disable-geo" => disable_geo = true,
            "--disable-time" => disable_time = true,
            "--audit-log" => audit_log = iter.next().cloned(),
            "--flow-capacity" => {
                if let Some(v) = iter.next() {
                    tuning.flow_capacity = v.parse().map_err(|_| "invalid flow capacity")?;
                }
            }
            "--flow-shards" => {
                if let Some(v) = iter.next() {
                    tuning.flow_shards = Some(v.parse().map_err(|_| "invalid flow shards")?);
                }
            }
            "--reassembly-buffer" => {
                if let Some(v) = iter.next() {
                    tuning.reassembly_buffer = v.parse().map_err(|_| "invalid reassembly buffer")?;
                }
            }
            "--signature-tail-budget" => {
                if let Some(v) = iter.next() {
                    tuning.signature_tail_budget =
                        v.parse().map_err(|_| "invalid signature tail budget")?;
                }
            }
            "--backpressure" => {
                if let Some(v) = iter.next() {
                    tuning.backpressure_mode = parse_backpressure(v)?;
                }
            }
            "--fail-open" => tuning.fail_mode = Some(FailMode::FailOpen),
            "--fail-closed" => tuning.fail_mode = Some(FailMode::FailClosed),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = resolve_config_path(&rules_path.ok_or("Missing --rules <file>")?, false)?;
    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let iface = iface.ok_or("Missing --iface <name>")?;

    let runtime_cfg = load_runtime_config(&config_root())?;
    let dp_cfg = runtime_cfg.dataplane;
    let summary = run_capture_pipeline(
        iface.as_str(),
        &rules_path,
        policies_path.as_deref(),
        &tuning,
        dp_cfg,
        count,
        audit_log.as_deref(),
        disable_logs,
        disable_ids,
        disable_ips,
        disable_geo,
        disable_time,
    )?;
    println!(
        "Async capture finished: allowed={} dropped={} flows={}",
        summary.counters.allowed,
        summary.counters.dropped,
        summary.flows.len()
    );
    Ok(())
}

fn build_manager(
    rules_path: &std::path::Path,
    policies_path: Option<&std::path::Path>,
    tuning: &Tuning,
    disable_logs: bool,
    disable_ids: bool,
    disable_ips: bool,
    disable_geo: bool,
    disable_time: bool,
) -> Result<FirewallManager, String> {
    let mut mgr = load_manager(rules_path, policies_path, tuning)?;
    if disable_logs {
        mgr.set_logging_enabled(false);
    }
    if disable_ids {
        mgr.set_ids_enabled(false);
    }
    if disable_ips {
        mgr.set_ips_enabled(false);
    }
    if disable_geo {
        mgr.set_geo_rules_enabled(false);
    }
    if disable_time {
        mgr.set_time_rules_enabled(false);
    }
    Ok(mgr)
}

fn summarize_manager(mgr: &FirewallManager) -> WorkerSummary {
    WorkerSummary {
        counters: mgr.counters(),
        flow_stats: mgr.flow_stats(),
        flows: mgr.flows(),
        alerts: mgr.alerts(None),
        suspicious: mgr.suspicious_flows(),
        rule_hits: mgr.rule_hits(),
        proto_counters: mgr.protocol_counters(),
    }
}

fn merge_worker_summaries(results: Vec<WorkerSummary>, processed: usize) -> CaptureSummary {
    let mut summary = CaptureSummary {
        processed,
        counters: FirewallCounters::default(),
        flow_stats: FlowStats::default(),
        flows: Vec::new(),
        alerts: Vec::new(),
        suspicious: Vec::new(),
        rule_hits: HashMap::new(),
        proto_counters: HashMap::new(),
    };
    for result in results {
        summary.counters.allowed += result.counters.allowed;
        summary.counters.dropped += result.counters.dropped;
        summary.flow_stats.packets += result.flow_stats.packets;
        summary.flow_stats.new_flows += result.flow_stats.new_flows;
        summary.flow_stats.evicted += result.flow_stats.evicted;
        summary.flows.extend(result.flows);
        summary.alerts.extend(result.alerts);
        summary.suspicious.extend(result.suspicious);
        for (rule, hits) in result.rule_hits {
            *summary.rule_hits.entry(rule).or_insert(0) += hits;
        }
        for (proto, hits) in result.proto_counters {
            *summary.proto_counters.entry(proto).or_insert(0) += hits;
        }
    }
    summary
}

fn resolve_shard_plan(dp_cfg: &DataplaneConfig) -> Result<ShardPlan, String> {
    let rss = match dp_cfg.rss.as_ref() {
        Some(rss) if rss.enabled => rss,
        _ => return Ok(ShardPlan::Single),
    };
    let affinity = rss.cpu_affinity.as_ref();
    match dp_cfg.backend {
        BackendKind::Pcap => {
            let workers = if let Some(cores) = affinity {
                if cores.is_empty() {
                    return Err("cpu_affinity cannot be empty".into());
                }
                cores.len()
            } else {
                rss.queues
                    .as_ref()
                    .map(|q| q.len())
                    .unwrap_or_else(|| {
                        std::thread::available_parallelism()
                            .map(|n| n.get())
                            .unwrap_or(1)
                    })
            };
            if workers > 1 {
                Ok(ShardPlan::Software { workers })
            } else {
                Ok(ShardPlan::Single)
            }
        }
        BackendKind::AfXdp => {
            let af_cfg = dp_cfg.af_xdp.clone().unwrap_or_default();
            let queues = rss.queues.clone().unwrap_or_else(|| {
                vec![af_cfg.queue.unwrap_or(0) as u16]
            });
            let queues = normalize_queue_list(queues, u16::MAX)?;
            if let Some(cores) = affinity {
                if cores.len() != queues.len() {
                    return Err("cpu_affinity length must match queue count".into());
                }
            }
            if queues.len() > 1 {
                Ok(ShardPlan::PerQueue { queues })
            } else {
                Ok(ShardPlan::Single)
            }
        }
        BackendKind::Dpdk => {
            let dpdk_cfg = dp_cfg.dpdk.clone().unwrap_or_default();
            if dpdk_cfg.rx_queues == 0 {
                return Err("dpdk rx_queues must be > 0".into());
            }
            let queues = rss
                .queues
                .clone()
                .unwrap_or_else(|| (0..dpdk_cfg.rx_queues).collect());
            let queues = normalize_queue_list(queues, dpdk_cfg.rx_queues)?;
            if let Some(cores) = affinity {
                if cores.len() != queues.len() {
                    return Err("cpu_affinity length must match queue count".into());
                }
            }
            if queues.len() > 1 {
                Ok(ShardPlan::PerQueue { queues })
            } else {
                Ok(ShardPlan::Single)
            }
        }
    }
}

fn normalize_queue_list(mut queues: Vec<u16>, max: u16) -> Result<Vec<u16>, String> {
    if queues.is_empty() {
        return Err("rss queue list is empty".into());
    }
    let mut seen = std::collections::HashSet::new();
    for q in &queues {
        if *q >= max {
            return Err(format!("rss queue {q} out of range"));
        }
        if !seen.insert(*q) {
            return Err("rss queue list contains duplicates".into());
        }
    }
    queues.shrink_to_fit();
    Ok(queues)
}

fn resolve_worker_core(
    rss: Option<&RssConfig>,
    worker_index: usize,
    worker_count: usize,
) -> Result<Option<usize>, String> {
    let cores = match rss.and_then(|r| r.cpu_affinity.as_ref()) {
        Some(cores) => cores,
        None => return Ok(None),
    };
    if cores.len() != worker_count {
        return Err("cpu_affinity length must match worker count".into());
    }
    cores
        .get(worker_index)
        .copied()
        .ok_or_else(|| "cpu_affinity index missing".to_string())
        .map(Some)
}

fn pin_current_thread(core_id: usize) -> Result<(), String> {
    let cores = core_affinity::get_core_ids().ok_or("cpu affinity unsupported")?;
    let target = cores
        .into_iter()
        .find(|core| core.id == core_id)
        .ok_or_else(|| format!("cpu core {core_id} not available"))?;
    if core_affinity::set_for_current(target) {
        Ok(())
    } else {
        Err(format!("failed to pin to cpu core {core_id}"))
    }
}

fn dataplane_config_for_queue(cfg: &DataplaneConfig, queue: u16) -> DataplaneConfig {
    let mut cfg = cfg.clone();
    match cfg.backend {
        BackendKind::Dpdk => {
            let mut dpdk = cfg.dpdk.clone().unwrap_or_default();
            dpdk.rx_queue = Some(queue);
            dpdk.tx_queue = Some(queue);
            cfg.dpdk = Some(dpdk);
        }
        BackendKind::AfXdp => {
            let mut af_xdp = cfg.af_xdp.clone().unwrap_or_default();
            af_xdp.queue = Some(queue as u32);
            cfg.af_xdp = Some(af_xdp);
        }
        BackendKind::Pcap => {}
    }
    cfg
}

fn run_capture_pipeline(
    iface: &str,
    rules_path: &std::path::Path,
    policies_path: Option<&std::path::Path>,
    tuning: &Tuning,
    dp_cfg: DataplaneConfig,
    count: usize,
    audit_log: Option<&str>,
    disable_logs: bool,
    disable_ids: bool,
    disable_ips: bool,
    disable_geo: bool,
    disable_time: bool,
) -> Result<CaptureSummary, String> {
    match resolve_shard_plan(&dp_cfg)? {
        ShardPlan::Single => run_capture_single(
            iface,
            rules_path,
            policies_path,
            tuning,
            &dp_cfg,
            count,
            audit_log,
            disable_logs,
            disable_ids,
            disable_ips,
            disable_geo,
            disable_time,
        ),
        ShardPlan::PerQueue { queues } => run_capture_per_queue(
            iface,
            rules_path,
            policies_path,
            tuning,
            &dp_cfg,
            queues,
            count,
            audit_log,
            disable_logs,
            disable_ids,
            disable_ips,
            disable_geo,
            disable_time,
        ),
        ShardPlan::Software { workers } => run_capture_software_sharded(
            iface,
            rules_path,
            policies_path,
            tuning,
            &dp_cfg,
            workers,
            count,
            audit_log,
            disable_logs,
            disable_ids,
            disable_ips,
            disable_geo,
            disable_time,
        ),
    }
}

fn run_capture_single(
    iface: &str,
    rules_path: &std::path::Path,
    policies_path: Option<&std::path::Path>,
    tuning: &Tuning,
    dp_cfg: &DataplaneConfig,
    count: usize,
    audit_log: Option<&str>,
    disable_logs: bool,
    disable_ids: bool,
    disable_ips: bool,
    disable_geo: bool,
    disable_time: bool,
) -> Result<CaptureSummary, String> {
    let mut mgr = build_manager(
        rules_path,
        policies_path,
        tuning,
        disable_logs,
        disable_ids,
        disable_ips,
        disable_geo,
        disable_time,
    )?;
    let capture_payload = capture_payload_enabled(&mgr);
    let mut dataplane =
        DataplaneHandle::open_live(iface, dp_cfg).map_err(|e| format!("dataplane: {e}"))?;
    if let Some(rss) = dp_cfg.rss.as_ref() {
        if rss.enabled && dp_cfg.backend != BackendKind::Pcap {
            dataplane
                .configure_rss(rss)
                .map_err(|e| format!("dataplane rss: {e}"))?;
        }
    }

    let mut processed = 0usize;
    while processed < count {
        match dataplane.next_frame() {
            Ok(Some(pkt)) => {
                let frame = FrameRef::from_view(&pkt);
                if let Ok(meta) =
                    packet_metadata(frame.bytes(), Direction::Ingress, capture_payload)
                {
                    let eval = mgr.evaluate(&meta, Some(iface), Instant::now());
                    if let Some(path) = &audit_log {
                        let _ = write_audit(path, &meta, &eval);
                    }
                    processed += 1;
                }
            }
            Ok(None) => continue,
            Err(e) => return Err(format!("dataplane read: {e}")),
        }
    }
    let summary = summarize_manager(&mgr);
    Ok(merge_worker_summaries(vec![summary], processed))
}

fn run_capture_per_queue(
    iface: &str,
    rules_path: &std::path::Path,
    policies_path: Option<&std::path::Path>,
    tuning: &Tuning,
    dp_cfg: &DataplaneConfig,
    queues: Vec<u16>,
    count: usize,
    audit_log: Option<&str>,
    disable_logs: bool,
    disable_ids: bool,
    disable_ips: bool,
    disable_geo: bool,
    disable_time: bool,
) -> Result<CaptureSummary, String> {
    let rss = dp_cfg.rss.as_ref();
    let processed = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(queues.len());
    let rules_path = rules_path.to_path_buf();
    let policies_path = policies_path.map(|p| p.to_path_buf());
    let audit_log = audit_log.map(|s| s.to_string());
    let tuning = tuning.clone();

    let worker_count = queues.len();
    for (worker_index, queue) in queues.into_iter().enumerate() {
        let core_id = resolve_worker_core(rss, worker_index, worker_count)?;
        let iface = iface.to_string();
        let rules_path = rules_path.clone();
        let policies_path = policies_path.clone();
        let audit_log = audit_log.clone();
        let tuning = tuning.clone();
        let dp_cfg = dataplane_config_for_queue(dp_cfg, queue);
        let processed = Arc::clone(&processed);
        let stop = Arc::clone(&stop);
        let handle = thread::spawn(move || -> Result<WorkerSummary, String> {
            if let Some(core_id) = core_id {
                pin_current_thread(core_id)?;
            }
            let mut mgr = build_manager(
                &rules_path,
                policies_path.as_deref(),
                &tuning,
                disable_logs,
                disable_ids,
                disable_ips,
                disable_geo,
                disable_time,
            )?;
            let capture_payload = capture_payload_enabled(&mgr);
            let mut dataplane =
                DataplaneHandle::open_live(&iface, &dp_cfg).map_err(|e| format!("dataplane: {e}"))?;
            if let Some(rss) = dp_cfg.rss.as_ref() {
                if rss.enabled {
                    let caps = dataplane.capabilities();
                    if !caps.supports_rss {
                        stop.store(true, Ordering::Release);
                        return Err("dataplane does not support rss".into());
                    }
                    dataplane
                        .configure_rss(rss)
                        .map_err(|e| {
                            stop.store(true, Ordering::Release);
                            format!("dataplane rss: {e}")
                        })?;
                }
            }

            while !stop.load(Ordering::Relaxed) {
                match dataplane.next_frame() {
                    Ok(Some(pkt)) => {
                        let idx = processed.fetch_add(1, Ordering::AcqRel);
                        if idx >= count {
                            stop.store(true, Ordering::Release);
                            break;
                        }
                        let frame = FrameRef::from_view(&pkt);
                        if let Ok(meta) =
                            packet_metadata(frame.bytes(), Direction::Ingress, capture_payload)
                        {
                            let eval = mgr.evaluate(&meta, Some(&iface), Instant::now());
                            if let Some(path) = &audit_log {
                                let _ = write_audit(path, &meta, &eval);
                            }
                        }
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        stop.store(true, Ordering::Release);
                        return Err(format!("dataplane read: {e}"));
                    }
                }
            }
            Ok(summarize_manager(&mgr))
        });
        handles.push(handle);
    }

    let mut results = Vec::with_capacity(handles.len());
    let mut error: Option<String> = None;
    for handle in handles {
        match handle.join() {
            Ok(Ok(summary)) => results.push(summary),
            Ok(Err(err)) => {
                if error.is_none() {
                    error = Some(err);
                }
            }
            Err(_) => {
                if error.is_none() {
                    error = Some("worker join failed".into());
                }
            }
        }
    }
    let processed = processed.load(Ordering::Acquire).min(count);
    if let Some(err) = error {
        return Err(err);
    }
    Ok(merge_worker_summaries(results, processed))
}

fn run_capture_software_sharded(
    iface: &str,
    rules_path: &std::path::Path,
    policies_path: Option<&std::path::Path>,
    tuning: &Tuning,
    dp_cfg: &DataplaneConfig,
    workers: usize,
    count: usize,
    audit_log: Option<&str>,
    disable_logs: bool,
    disable_ids: bool,
    disable_ips: bool,
    disable_geo: bool,
    disable_time: bool,
) -> Result<CaptureSummary, String> {
    let rss = dp_cfg
        .rss
        .as_ref()
        .ok_or("rss config missing for software sharding")?;
    let sharder = FlowSharder::new(rss, workers);
    let mut senders = Vec::with_capacity(workers);
    let mut handles = Vec::with_capacity(workers);
    let rules_path = rules_path.to_path_buf();
    let policies_path = policies_path.map(|p| p.to_path_buf());
    let audit_log = audit_log.map(|s| s.to_string());
    let tuning = tuning.clone();

    for worker_index in 0..workers {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1024);
        senders.push(tx);
        let core_id = resolve_worker_core(Some(rss), worker_index, workers)?;
        let rules_path = rules_path.clone();
        let policies_path = policies_path.clone();
        let audit_log = audit_log.clone();
        let tuning = tuning.clone();
        let iface = iface.to_string();
        let handle = thread::spawn(move || -> Result<WorkerSummary, String> {
            if let Some(core_id) = core_id {
                pin_current_thread(core_id)?;
            }
            let mut mgr = build_manager(
                &rules_path,
                policies_path.as_deref(),
                &tuning,
                disable_logs,
                disable_ids,
                disable_ips,
                disable_geo,
                disable_time,
            )?;
            let capture_payload = capture_payload_enabled(&mgr);
            for data in rx {
                if let Ok(meta) = packet_metadata(&data, Direction::Ingress, capture_payload) {
                    let eval = mgr.evaluate(&meta, Some(&iface), Instant::now());
                    if let Some(path) = &audit_log {
                        let _ = write_audit(path, &meta, &eval);
                    }
                }
            }
            Ok(summarize_manager(&mgr))
        });
        handles.push(handle);
    }

    let mut dataplane =
        DataplaneHandle::open_live(iface, dp_cfg).map_err(|e| format!("dataplane: {e}"))?;
    let mut processed = 0usize;
    let mut error: Option<String> = None;
    while processed < count {
        match dataplane.next_frame() {
            Ok(Some(pkt)) => {
                let bytes = pkt.bytes().to_vec();
                let idx = sharder.select_queue(&bytes);
                if senders[idx].send(bytes).is_err() {
                    error = Some("worker channel closed".into());
                    break;
                }
                processed += 1;
            }
            Ok(None) => continue,
            Err(e) => {
                error = Some(format!("dataplane read: {e}"));
                break;
            }
        }
    }
    drop(senders);

    let mut results = Vec::with_capacity(handles.len());
    let mut join_error: Option<String> = None;
    for handle in handles {
        match handle.join() {
            Ok(Ok(summary)) => results.push(summary),
            Ok(Err(err)) => {
                if join_error.is_none() {
                    join_error = Some(err);
                }
            }
            Err(_) => {
                if join_error.is_none() {
                    join_error = Some("worker join failed".into());
                }
            }
        }
    }
    if let Some(err) = join_error {
        return Err(err);
    }
    if let Some(err) = error {
        return Err(err);
    }
    Ok(merge_worker_summaries(results, processed))
}

fn cmd_replay(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut policies_path: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut direction: Option<Direction> = None;
    let mut iface: Option<String> = None;
    let mut disable_logs = false;
    let mut disable_ids = false;
    let mut disable_ips = false;
    let mut disable_geo = false;
    let mut disable_time = false;
    let mut audit_log: Option<String> = None;
    let mut block_rate_anomaly = false;
    let mut tuning = Tuning::default();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--policies" => policies_path = iter.next().cloned(),
            "--file" => file_path = iter.next().cloned(),
            "--direction" => {
                direction = iter
                    .next()
                    .map(|d| parse_direction(d))
                    .transpose()
                    .map_err(|e| format!("{e}"))?
            }
            "--iface" => iface = iter.next().cloned(),
            "--no-logs" => disable_logs = true,
            "--disable-ids" => disable_ids = true,
            "--disable-ips" => disable_ips = true,
            "--disable-geo" => disable_geo = true,
            "--disable-time" => disable_time = true,
            "--audit-log" => audit_log = iter.next().cloned(),
            "--block-rate-anomaly" => block_rate_anomaly = true,
            "--flow-capacity" => {
                if let Some(v) = iter.next() {
                    tuning.flow_capacity = v.parse().map_err(|_| "invalid flow capacity")?;
                }
            }
            "--flow-shards" => {
                if let Some(v) = iter.next() {
                    tuning.flow_shards = Some(v.parse().map_err(|_| "invalid flow shards")?);
                }
            }
            "--reassembly-buffer" => {
                if let Some(v) = iter.next() {
                    tuning.reassembly_buffer = v.parse().map_err(|_| "invalid reassembly buffer")?;
                }
            }
            "--signature-tail-budget" => {
                if let Some(v) = iter.next() {
                    tuning.signature_tail_budget =
                        v.parse().map_err(|_| "invalid signature tail budget")?;
                }
            }
            "--backpressure" => {
                if let Some(v) = iter.next() {
                    tuning.backpressure_mode = parse_backpressure(v)?;
                }
            }
            "--fail-open" => tuning.fail_mode = Some(FailMode::FailOpen),
            "--fail-closed" => tuning.fail_mode = Some(FailMode::FailClosed),
            other => return Err(format!("Unknown flag {other}")),
        }
    }

    let rules_path = resolve_config_path(&rules_path.ok_or("Missing --rules <file>")?, false)?;
    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let file_path = file_path.ok_or("Missing --file <hex_lines>")?;
    let direction = direction.ok_or("Missing --direction <ingress|egress>")?;

    let lines = read_rule_lines(&rules_path)?;
    let policy_lines = if let Some(p) = &policies_path {
        read_rule_lines(p)?
    } else {
        Vec::new()
    };
    let mut mgr = load_manager_from_lines(&lines, &policy_lines, &tuning)?;
    if disable_logs {
        mgr.set_logging_enabled(false);
    }
    if disable_ids {
        mgr.set_ids_enabled(false);
    }
    if disable_ips {
        mgr.set_ips_enabled(false);
    }
    if disable_geo {
        mgr.set_geo_rules_enabled(false);
    }
    if disable_time {
        mgr.set_time_rules_enabled(false);
    }
    if block_rate_anomaly {
        mgr.set_behavior_blocking(true);
    }
    let capture_payload = capture_payload_enabled(&mgr);

    let file = File::open(&file_path).map_err(|e| format!("open replay file: {e}"))?;
    let reader = BufReader::new(file);
    let mut blocked_by_protector = 0usize;
    let mut total = 0usize;
    let mut parse_drops = 0usize;
    for line in reader.lines() {
        let line = line.map_err(|e| format!("read packet line: {e}"))?;
        let cleaned = line.trim();
        if cleaned.is_empty() || cleaned.starts_with('#') {
            continue;
        }
        total += 1;
        let bytes = match hex_to_bytes(cleaned) {
            Ok(b) => b,
            Err(_) => {
                parse_drops += 1;
                continue;
            }
        };
        let meta = match packet_metadata(&bytes, direction, capture_payload) {
            Ok(m) => m,
            Err(_) => {
                parse_drops += 1;
                continue;
            }
        };
        let eval = mgr.evaluate(&meta, iface.as_deref(), Instant::now());
        if eval.blocked_by_protector {
            blocked_by_protector += 1;
        }
        if let Some(path) = &audit_log {
            let _ = write_audit(path, &meta, &eval);
        }
    }

    let alerts = mgr.alerts(None);
    let alerts_count = alerts.len();
    let rate_alerts = alerts
        .iter()
        .filter(|a| matches!(a.kind, BehaviorKind::RateAnomaly))
        .count();

    println!(
        "Replay done: packets={} allowed={} dropped={} blocked_by_protector={} flows={} alerts={} rate_alerts={}",
        total,
        mgr.counters().allowed,
        mgr.counters().dropped + parse_drops as u64,
        blocked_by_protector,
        mgr.flows().len(),
        alerts_count,
        rate_alerts,
    );
    Ok(())
}

fn cmd_failover(args: Vec<String>) -> Result<(), String> {
    let mut enable: Option<bool> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--enable" => enable = Some(true),
            "--disable" => enable = Some(false),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let mut mgr = FirewallManager::new(1024);
    if let Some(flag) = enable {
        mgr.set_failover_enabled(flag);
        println!("Failover enabled={}", flag);
    } else {
        println!("Failover enabled={}", mgr.failover_enabled());
    }
    Ok(())
}

fn cmd_metrics(args: Vec<String>) -> Result<(), String> {
    let mut rules_path: Option<String> = None;
    let mut policies_path: Option<String> = None;
    let mut iface: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--policies" => policies_path = iter.next().cloned(),
            "--iface" => iface = iter.next().cloned(),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = rules_path.ok_or("Missing --rules <file>")?;
    let rules_path = resolve_config_path(&rules_path, false)?;
    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let tuning = Tuning::default();
    let mgr = load_manager(&rules_path, policies_path.as_deref(), &tuning)?;
    let stats = mgr.flow_stats();
    println!(
        "Flow stats packets={} new_flows={} evicted={}",
        stats.packets, stats.new_flows, stats.evicted
    );
    println!("Flow capacity={}", mgr.flow_capacity());
    println!(
        "IDS enabled={} IPS enabled={} Failover enabled={}",
        mgr.ids_enabled(),
        mgr.ips_enabled(),
        mgr.failover_enabled()
    );
    println!(
        "Threat intel last updated: {:?}",
        mgr.threat_intel_updated_at()
    );
    println!("Protocol counters: {:?}", mgr.protocol_counters());
    if let Err(err) = print_dataplane_metrics(iface.as_deref()) {
        eprintln!("Dataplane metrics unavailable: {err}");
    }
    Ok(())
}

fn print_dataplane_metrics(iface: Option<&str>) -> Result<(), String> {
    let runtime = load_runtime_config(&config_root())?;
    let dp_cfg = runtime.dataplane;
    println!("Dataplane backend: {:?}", dp_cfg.backend);
    let iface = match iface {
        Some(name) => name,
        None => {
            println!("Dataplane stats: skipped (missing --iface)");
            return Ok(());
        }
    };
    let mut dp =
        DataplaneHandle::open_live(iface, &dp_cfg).map_err(|e| format!("open dataplane: {e}"))?;
    let stats = dp
        .stats()
        .map_err(|e| format!("dataplane stats: {e}"))?;
    println!(
        "Dataplane stats received={} dropped={} if_dropped={} tx={}",
        stats.received, stats.dropped, stats.if_dropped, stats.transmitted
    );
    match &mut dp {
        #[cfg(all(feature = "af-xdp", target_os = "linux"))]
        DataplaneHandle::AfXdp(inner) => {
            let stats = inner
                .stats()
                .map_err(|e| format!("af-xdp stats: {e}"))?;
            println!(
                "AF_XDP UMEM len={} hugepages={} numa_node={:?}",
                stats.umem_len, stats.umem_hugepages, stats.umem_numa_node
            );
        }
        #[cfg(all(feature = "dpdk", target_os = "linux"))]
        DataplaneHandle::Dpdk(inner) => {
            let stats = inner.stats().map_err(|e| format!("dpdk stats: {e}"))?;
            println!(
                "DPDK hugepages={} mempool_socket={:?} port_socket={:?}",
                stats.hugepages, stats.mempool_socket, stats.port_socket
            );
        }
        #[cfg(feature = "pcap")]
        DataplaneHandle::Pcap(_) => {}
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct HugepageInfo {
    total: u64,
    free: u64,
    size_kb: usize,
}

#[cfg(target_os = "linux")]
fn read_hugepage_info() -> Result<HugepageInfo, String> {
    let body = std::fs::read_to_string("/proc/meminfo")
        .map_err(|e| format!("read /proc/meminfo: {e}"))?;
    let mut total = None;
    let mut free = None;
    let mut size_kb = None;
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("HugePages_Total:") {
            total = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("HugePages_Free:") {
            free = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Hugepagesize:") {
            size_kb = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    match (total, free, size_kb) {
        (Some(total), Some(free), Some(size_kb)) => Ok(HugepageInfo {
            total,
            free,
            size_kb,
        }),
        _ => Err("hugepage info missing in /proc/meminfo".into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn read_hugepage_info() -> Result<HugepageInfo, String> {
    Err("hugepage info only available on linux".into())
}

#[cfg(target_os = "linux")]
fn list_numa_nodes() -> Result<Vec<u32>, String> {
    let root = std::path::Path::new("/sys/devices/system/node");
    let entries = std::fs::read_dir(root)
        .map_err(|e| format!("read {}: {e}", root.display()))?;
    let mut nodes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read node entry: {e}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix("node") {
            if let Ok(id) = rest.parse::<u32>() {
                nodes.push(id);
            }
        }
    }
    nodes.sort_unstable();
    if nodes.is_empty() {
        return Err("no NUMA nodes found in sysfs".into());
    }
    Ok(nodes)
}

#[cfg(not(target_os = "linux"))]
fn list_numa_nodes() -> Result<Vec<u32>, String> {
    Err("NUMA info only available on linux".into())
}

fn cmd_dataplane_diag(args: Vec<String>) -> Result<(), String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        return Err(format!("Unknown flag {arg}"));
    }
    let runtime = load_runtime_config(&config_root())?;
    let dp_cfg = runtime.dataplane;
    println!("Dataplane backend: {:?}", dp_cfg.backend);

    let mut warnings: Vec<String> = Vec::new();
    let mut issues: Vec<String> = Vec::new();

    let hugepages = read_hugepage_info();
    match &hugepages {
        Ok(info) => println!(
            "Hugepages total={} free={} size_kb={}",
            info.total, info.free, info.size_kb
        ),
        Err(err) => println!("Hugepages: unavailable ({err})"),
    }

    let numa_nodes = list_numa_nodes();
    match &numa_nodes {
        Ok(nodes) => println!("NUMA nodes: {:?}", nodes),
        Err(err) => println!("NUMA nodes: unavailable ({err})"),
    }

    match dp_cfg.backend {
        BackendKind::Pcap => {
            println!("Backend pcap: no hugepage or NUMA validation required.");
        }
        BackendKind::AfXdp => {
            if !cfg!(target_os = "linux") {
                issues.push("af-xdp backend requires linux".into());
            }
            let cfg = dp_cfg.af_xdp.clone().unwrap_or_default();
            validate_af_xdp_diag(&cfg, &hugepages, &numa_nodes, &mut warnings, &mut issues)?;
        }
        BackendKind::Dpdk => {
            if !cfg!(target_os = "linux") {
                issues.push("dpdk backend requires linux".into());
            }
            let cfg = dp_cfg.dpdk.clone().unwrap_or_default();
            validate_dpdk_diag(&cfg, &hugepages, &numa_nodes, &mut warnings, &mut issues)?;
        }
    }

    if !warnings.is_empty() {
        println!("Warnings:");
        for warn in warnings {
            println!("- {warn}");
        }
    }
    if !issues.is_empty() {
        println!("Issues:");
        for issue in issues {
            println!("- {issue}");
        }
        return Err("dataplane diagnostics failed".into());
    }

    println!("Dataplane diagnostics: OK");
    Ok(())
}

fn validate_af_xdp_diag(
    cfg: &dataplane::AfXdpConfig,
    hugepages: &Result<HugepageInfo, String>,
    numa_nodes: &Result<Vec<u32>, String>,
    warnings: &mut Vec<String>,
    issues: &mut Vec<String>,
) -> Result<(), String> {
    let frame_size = cfg.frame_size.max(2048);
    let frames = cfg.umem_frames.max(2048).next_power_of_two();
    let umem_len = frame_size
        .checked_mul(frames)
        .ok_or_else(|| "umem size overflow".to_string())?;

    if cfg.use_hugepages {
        match hugepages {
            Ok(info) => {
                let expected = cfg.hugepage_size_kb.unwrap_or(info.size_kb);
                if expected != info.size_kb {
                    let msg = format!(
                        "af-xdp hugepage size {}kb does not match system {}kb",
                        expected, info.size_kb
                    );
                    if cfg.hugepage_fallback {
                        warnings.push(msg);
                    } else {
                        issues.push(msg);
                    }
                }
                let size_bytes = expected.saturating_mul(1024);
                if size_bytes == 0 {
                    issues.push("af-xdp hugepage size invalid".into());
                } else if umem_len % size_bytes != 0 {
                    let msg = format!(
                        "af-xdp umem len {} not aligned to {} bytes",
                        umem_len, size_bytes
                    );
                    if cfg.hugepage_fallback {
                        warnings.push(msg);
                    } else {
                        issues.push(msg);
                    }
                } else {
                    let needed = (umem_len + size_bytes - 1) / size_bytes;
                    if info.free < needed as u64 {
                        let msg = format!(
                            "af-xdp needs {} hugepages, only {} free",
                            needed, info.free
                        );
                        if cfg.hugepage_fallback {
                            warnings.push(msg);
                        } else {
                            issues.push(msg);
                        }
                    }
                }
            }
            Err(err) => {
                let msg = format!("af-xdp hugepage info unavailable: {err}");
                if cfg.hugepage_fallback {
                    warnings.push(msg);
                } else {
                    issues.push(msg);
                }
            }
        }
    }

    if let Some(node) = cfg.numa_node {
        match numa_nodes {
            Ok(nodes) => {
                if !nodes.contains(&(node as u32)) {
                    let msg = format!("af-xdp NUMA node {node} not present");
                    if cfg.numa_fallback {
                        warnings.push(msg);
                    } else {
                        issues.push(msg);
                    }
                }
            }
            Err(err) => {
                let msg = format!("af-xdp NUMA info unavailable: {err}");
                if cfg.numa_fallback {
                    warnings.push(msg);
                } else {
                    issues.push(msg);
                }
            }
        }
    }
    Ok(())
}

fn validate_dpdk_diag(
    cfg: &dataplane::DpdkConfig,
    hugepages: &Result<HugepageInfo, String>,
    numa_nodes: &Result<Vec<u32>, String>,
    warnings: &mut Vec<String>,
    issues: &mut Vec<String>,
) -> Result<(), String> {
    let max_queues = cfg.rx_queues.max(cfg.tx_queues).max(1) as usize;
    if let Some(queues) = &cfg.queue_sockets {
        if queues.is_empty() {
            issues.push("dpdk queue-sockets cannot be empty".into());
        } else if queues.len() != 1 && queues.len() != max_queues {
            issues.push("dpdk queue-sockets length must be 1 or match max queues".into());
        }
    }

    if let Some(node) = cfg.socket_id {
        if let Ok(nodes) = numa_nodes {
            if !nodes.contains(&(node as u32)) {
                issues.push(format!("dpdk socket-id {node} not present"));
            }
        }
    }
    if let Some(queues) = &cfg.queue_sockets {
        if let Ok(nodes) = numa_nodes {
            for node in queues {
                if !nodes.contains(&(*node as u32)) {
                    issues.push(format!("dpdk queue-sockets node {node} not present"));
                }
            }
        }
    }
    if cfg.socket_id.is_some() || cfg.queue_sockets.is_some() {
        if numa_nodes.is_err() {
            warnings.push("dpdk NUMA nodes unavailable; cannot validate sockets".into());
        }
    }

    let hugepages_enabled = !cfg.no_huge
        && !cfg.eal_args.iter().any(|arg| arg == "--no-huge");
    if hugepages_enabled {
        match hugepages {
            Ok(info) => {
                if info.total == 0 || info.free == 0 {
                    let msg = format!(
                        "dpdk hugepages unavailable (total={}, free={})",
                        info.total, info.free
                    );
                    if cfg.hugepage_fallback {
                        warnings.push(msg);
                    } else {
                        issues.push(msg);
                    }
                }
            }
            Err(err) => {
                let msg = format!("dpdk hugepage info unavailable: {err}");
                if cfg.hugepage_fallback {
                    warnings.push(msg);
                } else {
                    issues.push(msg);
                }
            }
        }
    }
    Ok(())
}

fn cmd_set_flow_capacity(args: Vec<String>) -> Result<(), String> {
    let mut cap: Option<usize> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--capacity" => {
                cap = iter
                    .next()
                    .map(|s| {
                        s.parse::<usize>()
                            .map_err(|_| "invalid capacity".to_string())
                    })
                    .transpose()?
            }
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let cap = cap.ok_or("Missing --capacity <number>")?;
    let mut mgr = FirewallManager::new(cap);
    mgr.set_flow_capacity(cap);
    println!("Set flow capacity to {}", mgr.flow_capacity());
    Ok(())
}

fn cmd_audit_status() -> Result<(), String> {
    println!(
        "Config root={} readonly={}",
        config_root().display(),
        std::env::var("AEGIS_CONFIG_READONLY")
            .or_else(|_| std::env::var("FIREWALL_CONFIG_READONLY"))
            .unwrap_or_else(|_| "unset".into())
    );
    Ok(())
}

fn load_manager(
    rules_path: &std::path::Path,
    policies_path: Option<&std::path::Path>,
    tuning: &Tuning,
) -> Result<FirewallManager, String> {
    let lines = read_rule_lines(rules_path)?;
    let mut parsed_rules = Vec::new();
    for line in lines {
        let rule = parse_rule_line(&line)?;
        parsed_rules.push(rule);
    }
    validate_rules(&parsed_rules)?;
    let mut mgr = if let Some(shards) = tuning.flow_shards {
        FirewallManager::with_flow_shards(tuning.flow_capacity, shards)
    } else {
        FirewallManager::new(tuning.flow_capacity)
    };
    for rule in parsed_rules {
        mgr.add_rule(rule);
    }
    if let Some(path) = policies_path {
        let entries = read_rule_lines(path)?
            .into_iter()
            .map(|line| {
                let (prio, action, cond) = parse_policy_line(&line)?;
                Ok(PolicyEntry {
                    priority: prio,
                    action,
                    condition: cond,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        validate_policies(&entries)?;
        mgr.apply_policy_entries(entries);
    }
    mgr.set_reassembly_buffer(tuning.reassembly_buffer);
    mgr.set_signature_tail_budget(tuning.signature_tail_budget);
    mgr.set_dpi_scratch_budget(tuning.dpi_scratch_budget);
    mgr.set_backpressure_mode(tuning.backpressure_mode);
    let fail_mode = tuning.fail_mode.unwrap_or_else(resolve_fail_mode);
    mgr.set_fail_mode(fail_mode);
    Ok(mgr)
}

fn load_manager_from_lines(
    rules: &[String],
    policies: &[String],
    tuning: &Tuning,
) -> Result<FirewallManager, String> {
    let mut parsed_rules = Vec::new();
    for line in rules {
        let rule = parse_rule_line(line)?;
        parsed_rules.push(rule);
    }
    validate_rules(&parsed_rules)?;
    let mut mgr = if let Some(shards) = tuning.flow_shards {
        FirewallManager::with_flow_shards(tuning.flow_capacity, shards)
    } else {
        FirewallManager::new(tuning.flow_capacity)
    };
    for rule in parsed_rules {
        mgr.add_rule(rule);
    }
    if !policies.is_empty() {
        let entries = policies
            .iter()
            .map(|line| {
                let (prio, action, cond) = parse_policy_line(line)?;
                Ok(PolicyEntry {
                    priority: prio,
                    action,
                    condition: cond,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        validate_policies(&entries)?;
        mgr.apply_policy_entries(entries);
    }
    mgr.set_reassembly_buffer(tuning.reassembly_buffer);
    mgr.set_signature_tail_budget(tuning.signature_tail_budget);
    mgr.set_dpi_scratch_budget(tuning.dpi_scratch_budget);
    mgr.set_backpressure_mode(tuning.backpressure_mode);
    let fail_mode = tuning.fail_mode.unwrap_or_else(resolve_fail_mode);
    mgr.set_fail_mode(fail_mode);
    Ok(mgr)
}

fn append_rule_line(path: &std::path::Path, line: &str) -> Result<(), String> {
    enforce_writable(path)?;
    let mut file = File::options()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open rules file: {e}"))?;
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| format!("write rule: {e}"))
}

fn remove_rule_line(path: &std::path::Path, id: usize) -> Result<(), String> {
    enforce_writable(path)?;
    let lines = read_rule_lines(path)?;
    if id == 0 || id > lines.len() {
        return Err("rule id out of range".into());
    }
    let mut new_lines = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx + 1 != id {
            new_lines.push(line.clone());
        }
    }
    let mut file = File::create(path).map_err(|e| format!("rewrite rules: {e}"))?;
    for l in new_lines {
        file.write_all(l.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|e| format!("write: {e}"))?;
    }
    Ok(())
}

fn read_rule_lines(path: &std::path::Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(|e| format!("open rules: {e}"))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| format!("read rules: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        lines.push(trimmed.to_string());
    }
    Ok(lines)
}

fn packet_metadata(
    bytes: &[u8],
    direction: Direction,
    capture_payload: bool,
) -> Result<PacketMetadata, ParseError> {
    let packet = PacketRef::parse(bytes, direction)?;
    Ok(packet.materialize(capture_payload))
}

fn capture_payload_enabled(mgr: &FirewallManager) -> bool {
    mgr.ids_enabled() || mgr.ips_enabled()
}

pub(crate) fn detect_application(
    proto: IpProtocol,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> ApplicationType {
    static SIGNATURE_ENGINE: OnceLock<SignatureEngine> = OnceLock::new();
    let engine = SIGNATURE_ENGINE.get_or_init(SignatureEngine::with_default_rules);
    engine.detect_application(proto, src_port, dst_port, payload)
}

pub(crate) fn parse_tls_metadata(payload: &[u8]) -> Option<TlsMetadata> {
    if payload.len() < 6 {
        return None;
    }
    if payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    if payload.get(5).copied() != Some(0x01) {
        return None;
    }
    // Skip record header (5 bytes) + handshake header (4 bytes)
    if payload.len() < 9 {
        return None;
    }
    let mut idx = 9usize;
    // Version (2) + Random (32)
    if payload.len() < idx + 34 {
        return None;
    }
    idx += 34;
    // Session ID
    let sid_len = payload.get(idx).copied()? as usize;
    idx += 1 + sid_len;
    if payload.len() < idx + 2 {
        return None;
    }
    // Cipher suites vector
    let cipher_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    if payload.len() < idx + cipher_len {
        return None;
    }
    let mut cipher_suites = Vec::new();
    let mut cs_idx = idx;
    while cs_idx + 1 < idx + cipher_len {
        cipher_suites.push(u16::from_be_bytes([payload[cs_idx], payload[cs_idx + 1]]));
        cs_idx += 2;
    }
    idx += cipher_len;
    if payload.len() < idx + 1 {
        return Some(TlsMetadata {
            sni: None,
            cipher_suites,
        });
    }
    // Compression methods
    let comp_len = payload[idx] as usize;
    idx += 1 + comp_len;
    // Extensions length
    if payload.len() < idx + 2 {
        return Some(TlsMetadata {
            sni: None,
            cipher_suites,
        });
    }
    let ext_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
    idx += 2;
    let ext_end = idx.saturating_add(ext_len).min(payload.len());
    let mut sni: Option<String> = None;
    while idx + 4 <= ext_end {
        let etype = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let elen = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        idx += 4;
        if idx + elen > ext_end {
            break;
        }
        if etype == 0x00 {
            // SNI extension
            if idx + 5 <= ext_end {
                let list_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
                let name_type = payload[idx + 2];
                let name_len = u16::from_be_bytes([payload[idx + 3], payload[idx + 4]]) as usize;
                if name_type == 0 && idx + 5 + name_len <= ext_end && list_len >= name_len + 3 {
                    if let Ok(host) = std::str::from_utf8(&payload[idx + 5..idx + 5 + name_len]) {
                        sni = Some(host.to_string());
                    }
                }
            }
        }
        idx += elen;
    }
    Some(TlsMetadata { sni, cipher_suites })
}

fn parse_protocol(token: Option<&str>) -> Result<IpProtocol, String> {
    match token {
        Some("tcp") => Ok(IpProtocol::Tcp),
        Some("udp") => Ok(IpProtocol::Udp),
        Some("icmp") => Ok(IpProtocol::Icmpv4),
        Some("icmpv6") => Ok(IpProtocol::Icmpv6),
        Some(other) => Err(format!("unsupported protocol {other}")),
        None => Err("missing protocol".into()),
    }
}

fn parse_direction(token: &str) -> Result<Direction, String> {
    match token {
        "ingress" => Ok(Direction::Ingress),
        "egress" => Ok(Direction::Egress),
        _ => Err("direction must be ingress or egress".into()),
    }
}

fn parse_action(token: Option<&str>) -> Option<Result<Action, String>> {
    match token {
        Some("allow") => Some(Ok(Action::Allow)),
        Some("deny") => Some(Ok(Action::Deny)),
        Some(t) if t.starts_with("redirect") => {
            let iface = t.split_once(':').map(|(_, name)| name.to_string());
            Some(Ok(Action::Redirect { interface: iface }))
        }
        Some(other) => Some(Err(format!("unknown action {other}"))),
        None => None,
    }
}

fn parse_backpressure(token: &str) -> Result<BackpressureMode, String> {
    match token.to_ascii_lowercase().as_str() {
        "drop" => Ok(BackpressureMode::Drop),
        "bypass" => Ok(BackpressureMode::Bypass),
        "log" | "log-only" => Ok(BackpressureMode::LogOnly),
        other => Err(format!("unknown backpressure mode {other}")),
    }
}

fn resolve_fail_mode() -> FailMode {
    let env_open = std::env::var("AEGIS_FAIL_OPEN").ok();
    let env_closed = std::env::var("AEGIS_FAIL_CLOSED").ok();
    match (env_open.as_deref(), env_closed.as_deref()) {
        (Some("1"), Some("1")) => FailMode::FailClosed,
        (Some("1"), _) => FailMode::FailOpen,
        (_, Some("1")) => FailMode::FailClosed,
        _ => FailMode::FailClosed,
    }
}

fn write_audit(
    path: &str,
    meta: &PacketMetadata,
    eval: &aegis_core::Evaluation,
) -> Result<(), String> {
    use std::io::Write;
    let mut f = File::options()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open audit log: {e}"))?;
    let line = format!(
        "ts={:?} action={:?} blocked={} src={:?}:{:?} dst={:?}:{:?} proto={:?} app={:?} tls_sni={:?} path={:?}\n",
        std::time::SystemTime::now(),
        eval.action,
        eval.blocked_by_protector,
        meta.src_ip,
        meta.src_port,
        meta.dst_ip,
        meta.dst_port,
        meta.protocol,
        meta.application,
        meta.tls.as_ref().and_then(|t| t.sni.clone()),
        eval.path
    );
    f.write_all(line.as_bytes())
        .map_err(|e| format!("write audit: {e}"))
}

fn parse_rule_line(line: &str) -> Result<Rule, String> {
    let mut parts = line.split_whitespace();
    let first = parts.next().ok_or("empty rule line")?;

    // Support "default deny ingress" as a special case.
    if first == "default" {
        let action = parse_action(parts.next()).ok_or("missing default action")??;
        let dir_token = parts.next().ok_or("missing direction")?;
        let direction = parse_direction(dir_token)?;
        return Ok(Rule {
            action,
            subject: RuleSubject::Default,
            direction,
        });
    }

    let action = parse_action(Some(first)).ok_or("rule must start with allow/deny")??;
    let subject_token = parts.next().ok_or("missing rule subject")?;
    let subject = match subject_token {
        "cidr" => {
            let cidr_str = parts.next().ok_or("missing cidr value")?;
            let cidr = parse_cidr(cidr_str).map_err(|_| "invalid cidr")?;
            RuleSubject::Cidr { network: cidr }
        }
        "port" => {
            let proto = parse_protocol(parts.next())?;
            let range_str = parts.next().ok_or("missing port value")?;
            let range = if let Some((start, end)) = range_str.split_once('-') {
                PortRange::new(
                    start.parse().map_err(|_| "invalid port")?,
                    end.parse().map_err(|_| "invalid port")?,
                )
            } else {
                let port: u16 = range_str.parse().map_err(|_| "invalid port")?;
                PortRange::new(port, port)
            };
            RuleSubject::Port {
                protocol: proto,
                range,
            }
        }
        "proto" => {
            let proto = parse_protocol(parts.next())?;
            RuleSubject::Protocol { protocol: proto }
        }
        "default" => RuleSubject::Default,
        _ => return Err("unknown rule subject".into()),
    };

    let dir_token = parts.next().ok_or("missing direction")?;
    let direction = parse_direction(dir_token)?;

    Ok(Rule {
        action,
        subject,
        direction,
    })
}

fn parse_policy_line(line: &str) -> Result<(u32, Action, PolicyCondition), String> {
    let mut parts = line.split_whitespace();
    let mut priority: Option<u32> = None;
    let mut action: Option<Action> = None;
    let mut src: Option<Cidr> = None;
    let mut dst: Option<Cidr> = None;
    let mut users: Vec<String> = Vec::new();
    let mut apps: Vec<ApplicationType> = Vec::new();
    let mut geos: Vec<String> = Vec::new();
    let mut times: Vec<TimeWindow> = Vec::new();

    while let Some(tok) = parts.next() {
        match tok {
            "priority" => {
                priority = Some(
                    parts
                        .next()
                        .ok_or("missing priority")?
                        .parse()
                        .map_err(|_| "invalid priority")?,
                );
            }
            "action" => {
                let act_tok = parts.next().ok_or("missing action")?;
                action = match parse_action(Some(act_tok)) {
                    Some(Ok(a)) => Some(a),
                    _ => return Err("bad action".into()),
                };
            }
            "src" => {
                let v = parts.next().ok_or("missing src cidr")?;
                src = Some(parse_cidr(v).map_err(|_| "invalid src cidr")?);
            }
            "dst" => {
                let v = parts.next().ok_or("missing dst cidr")?;
                dst = Some(parse_cidr(v).map_err(|_| "invalid dst cidr")?);
            }
            "user" => {
                users.push(parts.next().ok_or("missing user")?.to_string());
            }
            "app" => {
                let v = parts.next().ok_or("missing app")?;
                if v != "any" {
                    apps.push(match v {
                        "http" => ApplicationType::Http,
                        "dns" => ApplicationType::Dns,
                        "tls" => ApplicationType::TlsClientHello,
                        _ => return Err("unknown app".into()),
                    });
                }
            }
            "geo" => {
                geos.push(parts.next().ok_or("missing geo")?.to_string());
            }
            "time" => {
                let v = parts.next().ok_or("missing time range")?;
                let (a, b) = v.split_once('-').ok_or("time must be HH-HH (24h)")?;
                let start = a.parse::<u8>().map_err(|_| "invalid start hour")?;
                let end = b.parse::<u8>().map_err(|_| "invalid end hour")?;
                if start > 23 || end > 23 {
                    return Err("hour must be 0-23".into());
                }
                times.push(TimeWindow {
                    start_hour: start,
                    end_hour: end,
                });
            }
            other => return Err(format!("unknown token {other}")),
        }
    }

    let priority = priority.ok_or("missing priority")?;
    let action = action.ok_or("missing action")?;
    let condition = PolicyCondition {
        src,
        dst,
        users,
        applications: apps,
        geos,
        time_windows: times,
    };
    Ok((priority, action, condition))
}

fn print_usage_and_exit() {
    eprintln!("Usage:");
    eprintln!("  aegis add-rule --rules rules.txt --rule \"allow cidr 10.0.0.0/8 ingress\"");
    eprintln!("  aegis remove-rule --rules rules.txt --id 1");
    eprintln!("  aegis list-rules --rules rules.txt");
    eprintln!(
        "  aegis add-policy --policies policies.txt --rule \"priority 10 action allow app http\""
    );
    eprintln!("  aegis remove-policy --policies policies.txt --id 1");
    eprintln!("  aegis list-policies --policies policies.txt");
    eprintln!(
        "  aegis eval --rules rules.txt --direction ingress --hex \"<hex bytes>\" [--iface eth0] [--disable-iface eth0] [--no-logs]"
    );
    eprintln!("  aegis capture --rules rules.txt --iface eth0 [--count 10] [--no-logs]");
    eprintln!("  aegis metrics --rules rules.txt [--policies policies.txt] [--iface eth0]");
    eprintln!("  aegis dataplane-diag");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes_rejects_odd_length() {
        assert!(hex_to_bytes("0").is_err());
        assert!(hex_to_bytes("0ff").is_err());
    }

    #[test]
    fn rule_parser_accepts_default_prefix() {
        let lines = vec!["default allow egress"];
        let rule = parse_rule_line(lines[0]).unwrap();
        assert!(matches!(rule.subject, RuleSubject::Default));
        assert_eq!(rule.action, Action::Allow);
        assert_eq!(rule.direction, Direction::Egress);
    }

    #[test]
    fn rule_parser_rejects_bad_input() {
        let bad = vec!["permit cidr 10.0.0.0/8 ingress"];
        assert!(parse_rule_line(bad[0]).is_err());
        let bad2 = vec!["allow port tcp notaport ingress"];
        assert!(parse_rule_line(bad2[0]).is_err());
    }

    #[test]
    fn dpi_detection_http_dns_tls() {
        // HTTP
        let app = detect_application(IpProtocol::Tcp, 1234, 80, b"GET / HTTP/1.1\r\n");
        assert_eq!(app, ApplicationType::Http);
        // DNS
        let mut dns_query = vec![0u8; 14];
        dns_query[4] = 0x00;
        dns_query[5] = 0x01; // qdcount = 1
        let app_dns = detect_application(IpProtocol::Udp, 1234, 53, &dns_query);
        assert_eq!(app_dns, ApplicationType::Dns);
        // TLS ClientHello
        let tls = [22u8, 3, 1, 0, 10, 1, 0, 0, 0, 0];
        let app_tls = detect_application(IpProtocol::Tcp, 443, 1234, &tls);
        assert_eq!(app_tls, ApplicationType::TlsClientHello);
        // File/FTP
        let ftp = b"STOR file.txt\r\n";
        let app_file = detect_application(IpProtocol::Tcp, 21, 1025, ftp);
        assert_eq!(app_file, ApplicationType::FileTransfer);
    }

    #[test]
    fn capture_payload_enabled_tracks_ids_ips() {
        let mut mgr = FirewallManager::new(128);
        assert!(capture_payload_enabled(&mgr));
        mgr.set_ids_enabled(false);
        assert!(capture_payload_enabled(&mgr));
        mgr.set_ips_enabled(false);
        assert!(!capture_payload_enabled(&mgr));
        mgr.set_ids_enabled(true);
        assert!(capture_payload_enabled(&mgr));
    }

    #[test]
    fn policy_parser_parses_conditions() {
        let (prio, action, cond) = parse_policy_line(
            "priority 10 action allow src 10.0.0.0/8 app http user alice geo US time 9-17",
        )
        .unwrap();
        assert_eq!(prio, 10);
        assert_eq!(action, Action::Allow);
        assert!(cond.src.is_some());
        assert_eq!(cond.applications, vec![ApplicationType::Http]);
        assert_eq!(cond.users, vec!["alice".to_string()]);
        assert_eq!(cond.geos, vec!["US".to_string()]);
        assert_eq!(cond.time_windows.len(), 1);
    }

    #[test]
    fn policy_parser_rejects_bad_time() {
        assert!(parse_policy_line("priority 1 action allow time 25-30").is_err());
        assert!(parse_policy_line("priority 1 action allow time 9-nope").is_err());
    }

    #[test]
    fn rss_cpu_affinity_sets_worker_count_for_pcap() {
        let mut cfg = DataplaneConfig::default();
        cfg.backend = BackendKind::Pcap;
        cfg.rss = Some(RssConfig {
            enabled: true,
            symmetric: false,
            hash_fields: vec![dataplane::RssHashField::Ipv4],
            seed: None,
            queues: None,
            cpu_affinity: Some(vec![0, 1]),
        });
        let plan = resolve_shard_plan(&cfg).unwrap();
        match plan {
            ShardPlan::Software { workers } => assert_eq!(workers, 2),
            other => panic!("unexpected plan: {other:?}"),
        }
    }

    #[test]
    fn rss_cpu_affinity_mismatch_errors() {
        let mut cfg = DataplaneConfig::default();
        cfg.backend = BackendKind::Dpdk;
        cfg.dpdk = Some(dataplane::DpdkConfig {
            rx_queues: 2,
            tx_queues: 2,
            ..dataplane::DpdkConfig::default()
        });
        cfg.rss = Some(RssConfig {
            enabled: true,
            symmetric: false,
            hash_fields: vec![dataplane::RssHashField::Ipv4],
            seed: None,
            queues: Some(vec![0, 1]),
            cpu_affinity: Some(vec![0]),
        });
        let err = resolve_shard_plan(&cfg).unwrap_err();
        assert!(err.contains("cpu_affinity length"));
    }
}
