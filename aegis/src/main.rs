#![forbid(unsafe_code)]

use aegis_core::{
    Action, ApplicationType, BehaviorKind, Cidr, Direction, FirewallManager, PacketMetadata,
    PolicyCondition, PolicyEntry, PortRange, Rule, RuleSubject, SignatureEngine, TimeWindow,
    TlsMetadata, parse_cidr,
};
use packet_parser::{
    EtherType, IpProtocol, ParseError, parse_ethernet_frame, parse_ipv4_packet, parse_ipv6_packet,
    parse_tcp_segment, parse_udp_datagram,
};
use pcap_shim::Capture;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::time::Instant;
use tokio::{runtime::Builder, sync::mpsc};
use utils::{
    config_root, enforce_writable, hex_to_bytes, hex_to_bytes_or_exit, resolve_config_path,
};

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
    let mut mgr = load_manager(&rules_path, policies_path.as_deref())?;
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
    let meta = packet_metadata(&bytes, direction).map_err(|e| format!("{e:?}"))?;
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
            let mut mgr = load_manager_from_lines(&lines, &policy_lines)?;
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
            let bytes = hex_to_bytes(line)?;
            let meta = packet_metadata(&bytes, direction).map_err(|e| format!("{e:?}"))?;
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
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = rules_path.ok_or("Missing --rules <file>")?;
    let rules_path = resolve_config_path(&rules_path, false)?;
    let iface = iface.ok_or("Missing --iface <name>")?;

    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let mut mgr = load_manager(&rules_path, policies_path.as_deref())?;
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
    let mut cap =
        Capture::open_live(iface.as_str(), 65535, true, 1_000).map_err(|e| format!("pcap: {e}"))?;

    let mut processed = 0usize;
    while processed < count {
        match cap.next() {
            Ok(Some(pkt)) => {
                if let Ok(meta) = packet_metadata(pkt.data, Direction::Ingress) {
                    let eval = mgr.evaluate(&meta, Some(&iface), Instant::now());
                    if let Some(path) = &audit_log {
                        let _ = write_audit(path, &meta, &eval);
                    }
                    processed += 1;
                }
            }
            Ok(None) => continue,
            Err(e) => return Err(format!("pcap read: {e}")),
        }
    }
    println!(
        "Capture finished: processed={} allowed={} dropped={}",
        processed,
        mgr.counters().allowed,
        mgr.counters().dropped
    );
    println!(
        "Flow stats: packets={} new_flows={} evicted={}",
        mgr.flow_stats().packets,
        mgr.flow_stats().new_flows,
        mgr.flow_stats().evicted
    );
    println!("Protocol counters: {:?}", mgr.protocol_counters());
    for snap in mgr.flows() {
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
    if !mgr.alerts(None).is_empty() {
        println!("Alerts:");
        for alert in mgr.alerts(Some(100)) {
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
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = resolve_config_path(&rules_path.ok_or("Missing --rules <file>")?, false)?;
    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let iface = iface.ok_or("Missing --iface <name>")?;

    let rt = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    rt.block_on(async move {
        let mut mgr = load_manager(&rules_path, policies_path.as_deref())?;
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

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        let iface_clone = iface.clone();
        let reader = tokio::task::spawn_blocking(move || -> Result<(), String> {
            let mut cap = Capture::open_live(iface_clone.as_str(), 65535, true, 1_000)
                .map_err(|e| format!("pcap: {e}"))?;
            let mut processed = 0usize;
            while processed < count {
                match cap.next() {
                    Ok(Some(pkt)) => {
                        if tx.blocking_send(pkt.data.to_vec()).is_err() {
                            break;
                        }
                        processed += 1;
                    }
                    Ok(None) => continue,
                    Err(e) => return Err(format!("pcap read: {e}")),
                }
            }
            Ok(())
        });

        while let Some(data) = rx.recv().await {
            if let Ok(meta) = packet_metadata(&data, Direction::Ingress) {
                let eval = mgr.evaluate(&meta, Some(&iface), Instant::now());
                if let Some(path) = &audit_log {
                    let _ = write_audit(path, &meta, &eval);
                }
            }
        }
        reader.await.map_err(|e| format!("reader join: {e}"))??;
        println!(
            "Async capture finished: allowed={} dropped={} flows={}",
            mgr.counters().allowed,
            mgr.counters().dropped,
            mgr.flows().len()
        );
        Ok::<(), String>(())
    })
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
    let mut mgr = load_manager_from_lines(&lines, &policy_lines)?;
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
        let meta = match packet_metadata(&bytes, direction) {
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
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--rules" => rules_path = iter.next().cloned(),
            "--policies" => policies_path = iter.next().cloned(),
            other => return Err(format!("Unknown flag {other}")),
        }
    }
    let rules_path = rules_path.ok_or("Missing --rules <file>")?;
    let rules_path = resolve_config_path(&rules_path, false)?;
    let policies_path = policies_path
        .map(|p| resolve_config_path(&p, false))
        .transpose()?;
    let mgr = load_manager(&rules_path, policies_path.as_deref())?;
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
) -> Result<FirewallManager, String> {
    let lines = read_rule_lines(rules_path)?;
    let mut mgr = FirewallManager::new(65535);
    for line in lines {
        let rule = parse_rule_line(&line)?;
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
        mgr.apply_policy_entries(entries);
    }
    Ok(mgr)
}

fn load_manager_from_lines(
    rules: &[String],
    policies: &[String],
) -> Result<FirewallManager, String> {
    let mut mgr = FirewallManager::new(65535);
    for line in rules {
        let rule = parse_rule_line(line)?;
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
        mgr.apply_policy_entries(entries);
    }
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

fn packet_metadata(bytes: &[u8], direction: Direction) -> Result<PacketMetadata, ParseError> {
    let eth = parse_ethernet_frame(bytes)?;
    match eth.ethertype {
        EtherType::Ipv4 => {
            let ip = parse_ipv4_packet(eth.payload)?;
            let src_ip = IpAddr::V4(Ipv4Addr::from(ip.source));
            let dst_ip = IpAddr::V4(Ipv4Addr::from(ip.destination));
            let (src_port, dst_port, tcp_flags, app, tls_meta, sigs, payload, seq) =
                match ip.protocol {
                    IpProtocol::Tcp => {
                        let tcp = parse_tcp_segment(ip.payload)?;
                        (
                            Some(tcp.source_port),
                            Some(tcp.destination_port),
                            Some(tcp.flags),
                            detect_application(
                                IpProtocol::Tcp,
                                tcp.source_port,
                                tcp.destination_port,
                                tcp.payload,
                            ),
                            parse_tls_metadata(tcp.payload),
                            detect_signatures(tcp.payload),
                            tcp.payload.to_vec(),
                            Some(tcp.sequence_number),
                        )
                    }
                    IpProtocol::Udp => {
                        let udp = parse_udp_datagram(ip.payload)?;
                        (
                            Some(udp.source_port),
                            Some(udp.destination_port),
                            None,
                            detect_application(
                                IpProtocol::Udp,
                                udp.source_port,
                                udp.destination_port,
                                udp.payload,
                            ),
                            None,
                            detect_signatures(udp.payload),
                            udp.payload.to_vec(),
                            None,
                        )
                    }
                    _ => (
                        None,
                        None,
                        None,
                        ApplicationType::Unknown,
                        None,
                        Vec::new(),
                        Vec::new(),
                        None,
                    ),
                };
            Ok(PacketMetadata {
                direction,
                src_ip,
                dst_ip,
                protocol: ip.protocol,
                src_port,
                dst_port,
                tcp_flags,
                application: app,
                seq_number: seq,
                payload,
                signatures: sigs,
                user: None,
                geo: None,
                tls: tls_meta,
            })
        }
        EtherType::Ipv6 => {
            let ip = parse_ipv6_packet(eth.payload)?;
            let src_ip = IpAddr::V6(Ipv6Addr::from(ip.source));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(ip.destination));
            let (src_port, dst_port, tcp_flags, app, tls_meta, sigs, payload, seq) =
                match ip.next_header {
                    IpProtocol::Tcp => {
                        let tcp = parse_tcp_segment(ip.payload)?;
                        (
                            Some(tcp.source_port),
                            Some(tcp.destination_port),
                            Some(tcp.flags),
                            detect_application(
                                IpProtocol::Tcp,
                                tcp.source_port,
                                tcp.destination_port,
                                tcp.payload,
                            ),
                            parse_tls_metadata(tcp.payload),
                            detect_signatures(tcp.payload),
                            tcp.payload.to_vec(),
                            Some(tcp.sequence_number),
                        )
                    }
                    IpProtocol::Udp => {
                        let udp = parse_udp_datagram(ip.payload)?;
                        (
                            Some(udp.source_port),
                            Some(udp.destination_port),
                            None,
                            detect_application(
                                IpProtocol::Udp,
                                udp.source_port,
                                udp.destination_port,
                                udp.payload,
                            ),
                            None,
                            detect_signatures(udp.payload),
                            udp.payload.to_vec(),
                            None,
                        )
                    }
                    _ => (
                        None,
                        None,
                        None,
                        ApplicationType::Unknown,
                        None,
                        Vec::new(),
                        Vec::new(),
                        None,
                    ),
                };
            Ok(PacketMetadata {
                direction,
                src_ip,
                dst_ip,
                protocol: ip.next_header,
                src_port,
                dst_port,
                tcp_flags,
                application: app,
                seq_number: seq,
                payload,
                signatures: sigs,
                user: None,
                geo: None,
                tls: tls_meta,
            })
        }
        _ => Err(ParseError::Unsupported("non-ip ethertype")),
    }
}

fn detect_application(
    proto: IpProtocol,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> ApplicationType {
    static SIGNATURE_ENGINE: OnceLock<SignatureEngine> = OnceLock::new();
    let engine = SIGNATURE_ENGINE.get_or_init(SignatureEngine::with_default_rules);
    engine.detect_application(proto, src_port, dst_port, payload)
}

fn detect_signatures(payload: &[u8]) -> Vec<String> {
    static SIGNATURE_ENGINE: OnceLock<SignatureEngine> = OnceLock::new();
    let engine = SIGNATURE_ENGINE.get_or_init(SignatureEngine::with_default_rules);
    engine.scan_exploits(payload)
}

fn parse_tls_metadata(payload: &[u8]) -> Option<TlsMetadata> {
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
}
