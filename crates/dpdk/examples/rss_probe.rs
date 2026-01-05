use aegis_dpdk::{DpdkConfig, DpdkDataplane, DpdkRssConfig, DpdkRssHashField};

fn main() {
    if let Err(err) = run() {
        eprintln!("rss_probe error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut iface = String::new();
    let mut port_id = None;
    let mut queues = None;
    let mut seed = None;
    let mut rx_queues = 1u16;
    let mut tx_queues = 1u16;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iface" => {
                iface = args.next().ok_or("missing value for --iface")?;
            }
            "--port" => {
                let val = args.next().ok_or("missing value for --port")?;
                port_id = Some(val.parse().map_err(|_| "invalid port id")?);
            }
            "--queues" => {
                let val = args.next().ok_or("missing value for --queues")?;
                queues = Some(parse_u16_list(&val)?);
            }
            "--seed" => {
                let val = args.next().ok_or("missing value for --seed")?;
                seed = Some(val.parse().map_err(|_| "invalid seed")?);
            }
            "--rx-queues" => {
                let val = args.next().ok_or("missing value for --rx-queues")?;
                rx_queues = val.parse().map_err(|_| "invalid rx queues")?;
            }
            "--tx-queues" => {
                let val = args.next().ok_or("missing value for --tx-queues")?;
                tx_queues = val.parse().map_err(|_| "invalid tx queues")?;
            }
            "--help" => {
                print_help();
                return Ok(());
            }
            other => {
                if iface.is_empty() {
                    iface = other.to_string();
                } else {
                    return Err(format!("unknown argument: {other}"));
                }
            }
        }
    }

    if iface.is_empty() && port_id.is_none() {
        print_help();
        return Err("provide --iface <name> or --port <id>".into());
    }

    let mut cfg = DpdkConfig::default();
    cfg.port_id = port_id;
    cfg.rx_queues = rx_queues;
    cfg.tx_queues = tx_queues;

    let mut dp = DpdkDataplane::open(&iface, &cfg).map_err(|e| e.to_string())?;
    let rss_cfg = DpdkRssConfig {
        enabled: true,
        symmetric: false,
        hash_fields: vec![
            DpdkRssHashField::Ipv4,
            DpdkRssHashField::Ipv6,
            DpdkRssHashField::Tcp,
            DpdkRssHashField::Udp,
        ],
        seed,
        queues,
    };
    dp.configure_rss(&rss_cfg).map_err(|e| e.to_string())?;

    let stats = dp.stats().map_err(|e| e.to_string())?;
    println!(
        "RSS configured: rx={} tx={} dropped={} imissed={}",
        stats.rx, stats.tx, stats.rx_dropped, stats.imissed
    );
    Ok(())
}

fn parse_u16_list(input: &str) -> Result<Vec<u16>, String> {
    if input.trim().is_empty() {
        return Err("empty queue list".into());
    }
    input
        .split(',')
        .map(|part| part.trim().parse::<u16>().map_err(|_| "invalid queue id".to_string()))
        .collect()
}

fn print_help() {
    println!(
        "Usage: rss_probe --iface <name> [--queues 0,1] [--seed N] [--rx-queues N] [--tx-queues N]\n\
         Usage: rss_probe --port <id> [--queues 0,1] [--seed N] [--rx-queues N] [--tx-queues N]"
    );
}
