use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    path::{Path,PathBuf},
    process::{Command, exit},
    sync::{mpsc, Arc, Mutex},
    net::{UdpSocket, SocketAddr},
    thread,
    time::{Duration, Instant},
};

use lazy_static::lazy_static;
use chrono::Local;
use serde_json::Value;
use std::os::unix::net::UnixStream;
use regex::Regex;
use ipnetwork::IpNetwork;
use std::io::Read;
#[cfg(feature = "async")]
use tokio::time::sleep;

const LOG_FILE: &str = "/var/log/traffic_inspector.log";
const SOCKET_PATH: &str = "/usr/local/var/run/netifyd/netifyd.sock";
const NETIFYD_BINARY: &str = "/usr/local/sbin/netifyd";
//const RULES_FILE: &str = "/root/traffic_inspector/rules.json";
const RULES_DIR: &str = "/root/traffic_inspector/rules";  // Diretório contendo arquivos JSON de regras
const CONFIG_FILE: &str = "/root/traffic_inspector/config.json";

lazy_static! {
    static ref NETIFYD_INTERFACE: Mutex<String> = Mutex::new(load_config().unwrap().3.clone());
    static ref IGNORED_PROTOCOLS: HashSet<String> = load_config().unwrap().0.clone();
    static ref IGNORED_IPS: HashSet<String> = load_config().unwrap().1.clone();
    static ref IGNORED_SNIS: Vec<(Regex, String)> = load_config().unwrap().2.clone();
    static ref URL_PATTERNS: Vec<(Regex, String, String, String)> = load_rules().unwrap().0.clone();
    static ref IS_VERBOSE: bool = load_config().unwrap().4;
}

fn load_config() -> Result<(HashSet<String>, HashSet<String>, Vec<(Regex, String)>, String, bool), String> {
    let mut file = File::open(CONFIG_FILE)
        .map_err(|e| format!("Failed to open config file: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Failed to read config file: {}", e))?;

    let config: Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;

    let interface = config["interface"].as_str().unwrap_or("em0").to_string();

    let ignored_protocols: HashSet<String> = config["ignored_protocols"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|protocol| protocol.as_str().map(String::from))
        .collect();

    let ignored_ips: HashSet<String> = config["ignored_ips"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|ip| ip.as_str().map(String::from))
        .collect();

    let ignored_snis: Vec<(Regex, String)> = config["ignored_snis"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|pattern| {
            let pattern_str = pattern["pattern"].as_str()?;
            let name = pattern["name"].as_str()?;
            Some((Regex::new(pattern_str).ok()?, name.to_string()))
        })
        .collect();

    let verbose = config["verbose"].as_bool().unwrap_or(false);

    Ok((ignored_protocols, ignored_ips, ignored_snis, interface, verbose))
}

fn load_rules() -> Result<(Vec<(Regex, String, String, String)>, bool), String> {
    let mut url_patterns: Vec<(Regex, String, String, String)> = Vec::new();
    let mut verbose = false;

    let paths = fs::read_dir(RULES_DIR)
        .map_err(|e| format!("Failed to read rules directory: {}", e))?;

    for path in paths {
        let path: PathBuf = path
            .map_err(|e| format!("Failed to read entry in rules directory: {}", e))?
            .path();

        if path.extension() == Some(std::ffi::OsStr::new("json")) {
            let mut file = File::open(&path)
                .map_err(|e| format!("Failed to open rules file {}: {}", path.display(), e))?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| format!("Failed to read rules file {}: {}", path.display(), e))?;

            let rules: Value = serde_json::from_str(&contents)
                .map_err(|e| format!("Failed to parse rules file {}: {}", path.display(), e))?;

            let file_url_patterns: Vec<(Regex, String, String, String)> = rules["url_patterns"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|pattern| {
                    if !pattern["enable"].as_bool().unwrap_or(false) {
                        return None;
                    }

                    let pattern_str = pattern["pattern"].as_str()?;
                    let name = pattern["name"].as_str()?;
                    let action = pattern["action"].as_str().unwrap_or("pass");
                    let hosts = pattern["hosts"].as_str().unwrap_or("*");

                    let regex = Regex::new(pattern_str).ok()?;

                    Some((regex, name.to_string(), action.to_string(), hosts.to_string()))
                })
                .collect();

            url_patterns.extend(file_url_patterns);

            verbose = rules["verbose"].as_bool().unwrap_or(verbose);
        }
    }

    Ok((url_patterns, verbose))
}

// Função para monitorar o diretório de regras
#[cfg(feature = "async")]
async fn monitor_rules() {
    use std::collections::HashMap;
    use std::fs::metadata;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::sleep;

    let mut last_modified_times: HashMap<PathBuf, SystemTime> = HashMap::new();

    log_message("Iniciando monitoramento das regras...", true);

    loop {
        match fs::read_dir(RULES_DIR) {
            Ok(paths) => {
                let mut has_changes = false;

                for path in paths.flatten() {
                    let path = path.path();
                    if path.extension() == Some(std::ffi::OsStr::new("json")) {
                        if let Ok(metadata) = metadata(&path) {
                            if let Ok(modified_time) = metadata.modified() {
                                let entry = last_modified_times.entry(path.clone()).or_insert(UNIX_EPOCH);
                                if *entry < modified_time {
                                    *entry = modified_time;
                                    has_changes = true;
                                }
                            }
                        }
                    }
                }

                if has_changes {
                    log_message("Regras atualizadas. Recarregando...", true);
                    match load_rules() {
                        Ok((rules, _)) => {
                            // Atualiza as regras globalmente
                            let mut patterns = URL_PATTERNS.lock().unwrap();
                            *patterns = rules;
                        }
                        Err(e) => {
                            log_message(&format!("Erro ao carregar regras: {}", e), true);
                        }
                    }
                }
            }
            Err(e) => {
                log_message(&format!("Erro ao ler diretório de regras: {}", e), true);
            }
        }

        sleep(Duration::from_secs(30)).await;
    }
}

fn is_url_pattern_matched(url: &str) -> Option<String> {

    // Imprime os padrões carregados para verificar se estão sendo preenchidos corretamente
    println!("Verificando padrões para URL: {}", url);
    println!("URL_PATTERNS: {:?}", *URL_PATTERNS);

    for (pattern, name, action, hosts) in URL_PATTERNS.iter() {
        if pattern.is_match(url) {
            //println!("Match encontrado para: {} -> padrão: {}", url, pattern);
        } else {
            //println!("Sem correspondência: {} -> padrão: {}", url, pattern);
        }
        if pattern.is_match(url) && action == "block" {
            return Some(name.clone());
        }
    }
    None
}

fn is_url_pattern_matched_snis(url: &str) -> Option<String> {
    for (pattern, name) in IGNORED_SNIS.iter() {
        if pattern.is_match(url) {
            return Some(name.clone());
        }
    }
    None
}

fn is_ignored_ip(ip: &str, verbose: bool) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(parsed_ip) => {
            for cidr in &*IGNORED_IPS {
                if let Ok(ip_network) = cidr.parse::<IpNetwork>() {
                    if ip_network.contains(parsed_ip) {
                        return true;
                    }
                }
            }
            false
        },
        Err(_) => {
            log_message(&format!("Invalid IP: {}", ip), verbose);
            false
        }
    }
}

fn ensure_directory_exists(file_path: &str) -> io::Result<()> {
    if let Some(parent) = Path::new(file_path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn log_message(message: &str, verbose: bool) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let log_entry = format!("{} - {}\n", timestamp, message);

    if ensure_directory_exists(LOG_FILE).is_ok() {
        if let Ok(mut file) = File::options().append(true).create(true).open(LOG_FILE) {
            if let Err(e) = file.write_all(log_entry.as_bytes()) {
                eprintln!("Failed to write to log file: {}", e);
            }
        }
    }

    if *IS_VERBOSE {
        println!("{}", log_entry);
    }
}

fn ensure_ipfw_is_enabled() -> Result<(), String> {
    let output = Command::new("kldstat")
        .arg("-v")
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err("Failed to check loaded modules".into());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    if !output_str.contains("ipfw") {
        log_message("ipfw module not loaded, attempting to load...", true);
        let load_output = Command::new("kldload")
            .arg("ipfw")
            .output()
            .map_err(|e| e.to_string())?;

        if !load_output.status.success() {
            return Err("Failed to load ipfw module".into());
        }
    }
    Ok(())
}

fn ensure_netifyd_running(verbose: bool) {
    let interface = NETIFYD_INTERFACE.lock().unwrap().clone();

    let status = Command::new("pgrep")
        .arg("-f")
        .arg(NETIFYD_BINARY)
        .status();

    match status {
        Ok(status) => {
            if status.success() {
                log_message("Netify service is already running. Stopping previous instance...", verbose);

                let kill_status = Command::new("pkill")
                    .arg("-9")
                    .arg("-af")
                    .arg(NETIFYD_BINARY)
                    .status();

                if let Ok(kill_status) = kill_status {
                    if kill_status.success() {
                        log_message("Successfully killed previous Netify instance.", verbose);
                    } else {
                        log_message("Failed to kill previous Netify instance.", verbose);
                        return;
                    }
                } else {
                    log_message("Failed to run pkill to stop previous Netify instance.", verbose);
                    return;
                }
            }

            log_message("Starting new Netify service...", verbose);
            let start_status = Command::new(NETIFYD_BINARY)
                .arg("-I")
                .arg(interface)
                .status();

            match start_status {
                Ok(start_status) if start_status.success() => {
                    log_message("Netify service started successfully.", verbose);
                }
                Ok(_) | Err(_) => {
                    log_message("Failed to start Netify service.", verbose);
                    exit(1);
                }
            }
        }
        Err(_) => {
            log_message("Failed to check Netify service status.", verbose);
            exit(1);
        }
    }
}

fn is_protocol_ignored(protocol: &str) -> bool {
    IGNORED_PROTOCOLS.contains(protocol)
}

fn delete_ip_from_ipfw(ip: &str, verbose: bool) {
    if !ip.is_empty() {
        let output = Command::new("ipfw")
            .arg("delete")
            .arg(ip)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                log_message(&format!("Successfully removed IP {} from ipfw.", ip), verbose);
            }
            Ok(output) => {
                log_message(&format!(
                    "Failed to remove IP {} from ipfw. Error: {}",
                    ip,
                    String::from_utf8_lossy(&output.stderr)
                ), verbose);
            }
            Err(e) => {
                log_message(&format!("Error executing ipfw delete: {}", e), verbose);
            }
        }
    }
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

fn analyze_data_internal<F>(
    data: &str,
    tx_send: F,
    verbose: bool,
) where
    F: Fn(String) -> Result<(), Box<dyn std::error::Error>>,
{
    let mut buffer = String::new();

    for line in data.lines() {
        buffer.push_str(line);

        match serde_json::from_str::<Value>(&buffer) {
            Ok(parsed) => {
                buffer.clear();

                if let Some(flow) = parsed.get("flow") {
                    let local_ip = flow.get("local_ip").and_then(Value::as_str).unwrap_or("");
                    let local_mac = flow.get("local_mac").and_then(Value::as_str).unwrap_or("");

                    if local_ip.is_empty() || local_mac.is_empty() {
                        continue;
                    }

                    let dns_host_name = flow.get("dns_host_name").and_then(Value::as_str).unwrap_or("N/A");
                    let host_server_name = flow.get("host_server_name").and_then(Value::as_str).unwrap_or("N/A");
                    let client_sni = flow
                        .get("ssl")
                        .and_then(|ssl| ssl.get("client_sni"))
                        .and_then(Value::as_str)
                        .unwrap_or("N/A");
                    let protocol = flow.get("detected_protocol_name").and_then(Value::as_str).unwrap_or("N/A");
                    let other_ip = flow.get("other_ip").and_then(Value::as_str).unwrap_or("N/A");
                    let other_mac = flow.get("other_mac").and_then(Value::as_str).unwrap_or("N/A");
                    let other_port = flow.get("other_port").and_then(Value::as_str).unwrap_or("N/A");

                    if is_protocol_ignored(protocol) {
                        log_message("Ignoring block due to protocol presence.", verbose);
                        continue;
                    }

                    let should_not_block = is_url_pattern_matched_snis(client_sni)
                        .is_some()
                        && !is_url_pattern_matched(dns_host_name).is_some()
                        && !is_url_pattern_matched(host_server_name).is_some();

                    let should_block = is_url_pattern_matched(dns_host_name)
                        .or_else(|| is_url_pattern_matched(host_server_name))
                        .is_some()
                        && !should_not_block;

                    let is_ignored_ip = is_valid_ip(other_ip) && is_ignored_ip(other_ip, verbose);

                    let state = if is_ignored_ip {
                        log_message("Ignoring block due to IP in the ignored list.", verbose);
                        "access_ok"
                    } else if should_block {
                        log_message("Blocking domain as it matches a URL pattern.", verbose);
                        "block"
                    } else if should_not_block {
                        delete_ip_from_ipfw(other_ip, verbose);
                        log_message("Ignoring block due to URL in the ignored list.", verbose);
                        "access_ok"
                    } else {
                        "access_ok"
                    };

                    let analysis_output = format!(
                        "Local IP: {} \
                         Local Mac: {} \
                         DNS Host: {} \
                         Host Server Name: {} \
                         Client SNI: {} \
                         External IP: {} \
                         External Mac: {} \
                         External Port: {} \
                         Protocol: {} \
                         Action: {}",
                        local_ip, local_mac, dns_host_name, host_server_name, client_sni, other_ip, other_mac, other_port, protocol, state
                    );

                    log_message(&analysis_output, verbose);

                    if state == "block" {
                        /*let redirect_ip = "127.0.0.1";
                        if let Err(e) = add_firewall_redirect_rule(other_ip, redirect_ip, local_ip, verbose) {
                            log_message(&format!("Failed to add redirect rule: {}", e), verbose);
                        }*/
                        if tx_send(other_ip.to_string()).is_err() {
                            log_message("Failed to send blocked IP.", verbose);
                        }
                    }
                }
            }
            Err(e) => {
                log_message(&format!("Invalid JSON: {:?} Error: {:?}", buffer, e), verbose);
                buffer.clear();
            }
            _ => continue,
        }
    }
}

#[cfg(feature = "async")]
async fn analyze_data(data: &str, tx: tokio::sync::mpsc::Sender<String>, verbose: bool) {
    analyze_data_internal(data, |ip| tx.blocking_send(ip).map_err(|e| e.into()), verbose);
}

#[cfg(not(feature = "async"))]
fn analyze_data(data: &str, tx: std::sync::mpsc::Sender<String>, verbose: bool) {
    analyze_data_internal(data, |ip| tx.send(ip).map_err(|e| e.into()), verbose);
}

fn add_firewall_redirect_rule(src_ip: &str, redirect_ip: &str, local_ip: &str, verbose: bool) -> Result<(), std::io::Error> {
    let command = format!("ipfw add fwd {},48083 tcp from {} to {}", redirect_ip, local_ip, src_ip);
    log_message(&format!("Executing command: {}", command), verbose);

    let status = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .status()?;

    if status.success() {
        log_message("Firewall redirect rule added successfully.", verbose);
        Ok(())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to execute ipfw command"))
    }
}

fn block_ip(ip: &str, verbose: bool) {
    log_message(&format!("Blocking IP: {}", ip), verbose);

    let output = Command::new("ipfw")
        .arg("add")
        .arg("deny")
        .arg("ip")
        .arg("from")
        .arg(ip)
        .arg("to")
        .arg("any")
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                log_message(
                    &format!(
                        "Failed to block IP: {}. Error: {}",
                        ip,
                        String::from_utf8_lossy(&output.stderr)
                    ),
                    verbose,
                );
            }
        }
        Err(e) => log_message(&format!("Error executing ipfw: {}", e), verbose),
    }
}

fn process_ip_queue(rx: Arc<Mutex<mpsc::Receiver<String>>>, verbose: bool) {
    let mut blocked_ips = HashSet::new();

    loop {
        let ip = {
            let rx = rx.lock().unwrap();
            match rx.recv() {
                Ok(ip) => ip,
                Err(_) => {
                    log_message("Channel closed, terminating IP processing thread.", verbose);
                    break;
                }
            }
        };

        if !blocked_ips.contains(&ip) {
            block_ip(&ip, verbose);
            blocked_ips.insert(ip);
        }
    }
}

fn process_socket_data(tx: mpsc::Sender<String>, verbose: bool) -> io::Result<()> {
    #[cfg(feature = "async")]
    let connect_and_process = async {
        loop {
            match UnixStream::connect(SOCKET_PATH) {
                Ok(stream) => {
                    let reader = tokio::io::BufReader::new(tokio::net::UnixStream::from_std(stream)?);
                    let mut lines = reader.lines();

                    while let Some(line) = lines.next_line().await? {
                        analyze_data(&line, tx.clone(), verbose).await;
                    }
                }
                Err(e) => {
                    log_message(&format!("Socket connection error: {}. Retrying in 5 seconds...", e), verbose);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    };

    #[cfg(not(feature = "async"))]
    let connect_and_process = || {
        loop {
            match UnixStream::connect(SOCKET_PATH) {
                Ok(stream) => {
                    let reader = BufReader::new(stream);
                    for line in reader.lines() {
                        if let Ok(data) = line {
                            analyze_data(&data, tx.clone(), verbose);
                        }
                    }
                }
                Err(e) => {
                    log_message(&format!("Socket connection error: {}. Retrying in 5 seconds...", e), verbose);
                    thread::sleep(Duration::from_secs(5));
                }
            }
        }
    };

    #[cfg(feature = "async")]
    tokio::spawn(connect_and_process);

    #[cfg(not(feature = "async"))]
    connect_and_process();

    Ok(())
}

fn main() {
    #[cfg(feature = "async")]
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    #[cfg(feature = "async")]
    tokio::spawn(monitor_rules());

    #[cfg(feature = "async")]
    runtime.block_on(async {
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(100);
        let rx_clone = Arc::new(Mutex::new(rx));

        tokio::spawn(async move {
            process_ip_queue(rx_clone, true).await;
        });

        ensure_netifyd_running(true).await;
        ensure_ipfw_is_enabled().await.unwrap();

        if let Err(e) = process_socket_data(tx, true).await {
            eprintln!("Error in processing socket data: {}", e);
        }
    });

    #[cfg(not(feature = "async"))]
    {
        let (tx, rx) = mpsc::channel::<String>();
        let rx_clone = Arc::new(Mutex::new(rx));

        thread::spawn(move || {
            process_ip_queue(rx_clone, true);
        });

        ensure_netifyd_running(true);
        ensure_ipfw_is_enabled().unwrap();

        if let Err(e) = process_socket_data(tx, true) {
            eprintln!("Error in processing socket data: {}", e);
        }
    }
}
