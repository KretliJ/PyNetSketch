use pyo3::prelude::*;
use std::net::TcpStream;
use std::time::{Duration, Instant};
use rayon::prelude::*;
use std::sync::Arc;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use pnet::datalink::Config;
use std::io::ErrorKind;
use std::io::Write;
use std::collections::HashMap;

/// Helper for Python — logs a string message via the Python callback.
/// Errors are printed to stderr rather than silently discarded.
fn log_to_python(callback: &Py<PyAny>, message: String) {
    Python::with_gil(|py| {
        if let Err(e) = callback.call1(py, (message,)) {
            eprintln!("[Rust] log_to_python callback error: {}", e);
        }
    });
}

/// Debug helper: List interfaces
#[pyfunction]
fn rust_list_interfaces() -> Vec<String> {
    let interfaces = datalink::interfaces();
    interfaces.iter().map(|iface| iface.name.clone()).collect()
}

// --- 1. Fast Port Scanner ---
#[pyfunction]
fn rust_scan_ports(py: Python, ip: &str, ports: Vec<u16>, callback: Py<PyAny>) -> Vec<u16> {
    let callback_arc = Arc::new(callback);
    py.allow_threads(|| {
        ports.par_iter()
            .filter_map(|&port| {
                let address = format!("{}:{}", ip, port);
                // Use match instead of unwrap() — an unparseable address skips gracefully
                // instead of panicking the rayon thread pool.
                let socket_addr = match address.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        eprintln!("[Rust] rust_scan_ports: invalid address '{}': {}", address, e);
                        return None;
                    }
                };
                if TcpStream::connect_timeout(&socket_addr, Duration::from_millis(300)).is_ok() {
                    let msg = format!("[OPEN] Port {} (Detected by Rust)", port);
                    let cb_ref = Arc::clone(&callback_arc);
                    log_to_python(&cb_ref, msg);
                    Some(port)
                } else {
                    None
                }
            })
            .collect()
    })
}

// --- 2. Multi-Threaded TCP Ping ---
#[pyfunction]
fn rust_tcp_ping(ip: &str, port: u16, timeout_ms: u64) -> (bool, f64) {
    let address = format!("{}:{}", ip, port);
    let start = Instant::now();
    match address.parse() {
        Ok(socket_addr) => {
            if let Ok(_stream) = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
                return (true, start.elapsed().as_secs_f64() * 1000.0);
            }
        },
        Err(_) => return (false, 0.0),
    }
    (false, 0.0)
}

// --- 3. Subnet Sweeper ---
#[pyfunction]
fn rust_subnet_sweep(py: Python, ips: Vec<String>, ports: Vec<u16>, timeout_ms: u64, callback: Py<PyAny>) -> Vec<(String, u16, f64)> {
    let callback_arc = Arc::new(callback);
    py.allow_threads(|| {
        ips.par_iter()
            .flat_map(|ip| {
                let cb_outer = Arc::clone(&callback_arc);
                ports.par_iter().filter_map(move |&port| {
                    let address = format!("{}:{}", ip, port);
                    // Use match instead of unwrap() — skips unparseable addresses gracefully
                    // instead of panicking the rayon thread pool.
                    let socket_addr = match address.parse() {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("[Rust] rust_subnet_sweep: invalid address '{}': {}", address, e);
                            return None;
                        }
                    };
                    let start = Instant::now();
                    if TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)).is_ok() {
                        let latency = start.elapsed().as_secs_f64() * 1000.0;
                        let msg = format!("Host {} is UP (Port {} - {:.2}ms) [Rust]", ip, port, latency);
                        log_to_python(&cb_outer, msg);
                        Some((ip.clone(), port, latency))
                    } else {
                        None
                    }
                })
            })
            .collect()
    })
}

#[pyfunction]
#[pyo3(signature = (callback, interface_name=None, filter_ip=None))]
fn start_sniffer(
    py: Python,
    callback: PyObject,
    interface_name: Option<String>,
    filter_ip: Option<String>
) -> PyResult<()> {

    let interfaces = datalink::interfaces();
    let interface = match interface_name {
        Some(name) => interfaces.into_iter().find(|iface| iface.name == name)
                                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Interface not found"))?,
        None => interfaces.into_iter().find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
                                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("No suitable interface found"))?
    };

    // 100ms read timeout so the loop wakes frequently enough to check the stop signal
    let mut config = Config::default();
    config.read_timeout = Some(Duration::from_millis(100));

    let (_, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unhandled channel type")),
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyOSError, _>(format!("Failed to create channel: {}", e))),
    };

    let _ = std::io::stdout().flush();

    py.allow_threads(move || {
        let mut total_count: u64 = 0;
        let mut filtered_count: u64 = 0;
        let mut ip_counts: HashMap<String, u32> = HashMap::new();
        let mut last_report = Instant::now();

        loop {
            // Report once per second and ask Python whether to continue.
            // This is the only stop-check point. The idle/timeout path simply
            // continues back to this check, keeping stop latency under ~1.1s
            // even on quiet networks.
            if last_report.elapsed() >= Duration::from_secs(1) {
                let t_pps = total_count;
                let f_pps = filtered_count;
                // top_ips does not need mut — collected once and immediately moved
                let top_ips: Vec<(String, u32)> = ip_counts.iter()
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();

                total_count = 0;
                filtered_count = 0;
                ip_counts.clear();
                last_report = Instant::now();

                let should_continue = Python::with_gil(|py| {
                    match callback.call1(py, ((t_pps, f_pps, top_ips),)) {
                        Ok(result) => result.extract::<bool>(py).unwrap_or(true),
                        Err(e) => {
                            eprintln!("[Rust] sniffer callback error: {}", e);
                            false
                        }
                    }
                });

                if !should_continue {
                    break;
                }
            }

            match rx.next() {
                Ok(packet) => {
                    total_count += 1;

                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        match ethernet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                                    let src = header.get_source().to_string();
                                    *ip_counts.entry(src.clone()).or_insert(0) += 1;

                                    if let Some(ref target_ip) = filter_ip {
                                        let dst = header.get_destination().to_string();
                                        if src == *target_ip || dst == *target_ip {
                                            filtered_count += 1;
                                        }
                                    } else {
                                        filtered_count += 1;
                                    }
                                }
                            },
                            // Handle 802.1Q VLAN-tagged frames: unwrap the tag and
                            // process the inner IPv4 packet so tagged traffic is counted.
                            EtherTypes::Vlan => {
                                if let Some(vlan) = VlanPacket::new(ethernet.payload()) {
                                    if vlan.get_ethertype() == EtherTypes::Ipv4 {
                                        if let Some(header) = Ipv4Packet::new(vlan.payload()) {
                                            let src = header.get_source().to_string();
                                            *ip_counts.entry(src.clone()).or_insert(0) += 1;

                                            if let Some(ref target_ip) = filter_ip {
                                                let dst = header.get_destination().to_string();
                                                if src == *target_ip || dst == *target_ip {
                                                    filtered_count += 1;
                                                }
                                            } else {
                                                filtered_count += 1;
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {}
                        }
                    }
                },
                Err(e) => {
                    match e.kind() {
                        // TimedOut is normal on idle networks — just loop back so
                        // the 1s report boundary gets checked promptly.
                        ErrorKind::TimedOut => continue,
                        _ => {
                            eprintln!("[Rust] sniffer read error: {}", e);
                            continue;
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

// Function wrappers
#[pymodule]
fn pynetsketch_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rust_scan_ports, m)?)?;
    m.add_function(wrap_pyfunction!(rust_tcp_ping, m)?)?;
    m.add_function(wrap_pyfunction!(rust_subnet_sweep, m)?)?;
    m.add_function(wrap_pyfunction!(start_sniffer, m)?)?;
    m.add_function(wrap_pyfunction!(rust_list_interfaces, m)?)?;
    Ok(())
}