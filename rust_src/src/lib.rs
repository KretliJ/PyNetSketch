use pyo3::prelude::*;
use std::net::TcpStream;
use std::time::{Duration, Instant};
use rayon::prelude::*; // Parallel iteration
use std::sync::Arc; // Import Arc for thread-safe reference counting
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

// Removed unused import: use std::thread;

/// Helper function to send a log message back to Python
fn log_to_python(callback: &Py<PyAny>, message: String) {
    Python::with_gil(|py| {
        // We ignore errors (e.g. if app closed) to keep the thread running
        let _ = callback.call1(py, (message,));
    });
}

// --- 1. Fast Port Scanner ---
#[pyfunction]
fn rust_scan_ports(py: Python, ip: &str, ports: Vec<u16>, callback: Py<PyAny>) -> Vec<u16> {
    let callback_arc = Arc::new(callback);

    py.allow_threads(|| {
        ports.par_iter()
            .filter_map(|&port| {
                let address = format!("{}:{}", ip, port);
                if TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(300)).is_ok() {
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
                let duration = start.elapsed();
                return (true, duration.as_secs_f64() * 1000.0);
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
                    let start = Instant::now();
                    
                    if TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(timeout_ms)).is_ok() {
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

// --- 4. Traffic Sniffer (Corrected) ---
/// Inicia o sniffer.
/// Note: The argument order has been changed to place the required 'callback' first.
/// Python usage: start_sniffer(callback, interface_name=None, filter_ip=None)
#[pyfunction]
#[pyo3(signature = (callback, interface_name=None, filter_ip=None))]
fn start_sniffer(
    py: Python,
    callback: PyObject,
    interface_name: Option<String>,
    filter_ip: Option<String>
) -> PyResult<()> {
    
    // 1. Setup da Interface (Igual ao anterior)
    let interfaces = datalink::interfaces();
    let interface = match interface_name {
        Some(name) => interfaces.into_iter().find(|iface| iface.name == name)
                                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Interface not found"))?,
        None => interfaces.into_iter().find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
                                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("No suitable interface found"))?
    };

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unhandled channel type")),
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyOSError, _>(format!("Failed to create channel: {}", e))),
    };

    // 2. Loop Principal (Com GIL liberado)
    py.allow_threads(move || {
        let mut total_count = 0;
        let mut filtered_count = 0;
        let mut last_report = Instant::now();

        loop {
            // Reportar a cada 1 segundo
            if last_report.elapsed() >= Duration::from_secs(1) {
                let t_pps = total_count;
                let f_pps = filtered_count;
                
                // Reset contadores
                total_count = 0;
                filtered_count = 0;
                last_report = Instant::now();

                // Envia TUPLA (total, filtrado) para o Python
                Python::with_gil(|py| {
                    // Note os parênteses duplos: ((dados),) é um argumento que é uma tupla
                    let _ = callback.call1(py, ((t_pps, f_pps),));
                });
            }

            match rx.next() {
                Ok(packet) => {
                    // Sempre incrementa o tráfego total da interface
                    total_count += 1;

                    // Lógica de Filtro (Separada para apenas incrementar o contador específico)
                    if let Some(ref target_ip) = filter_ip {
                        let ethernet = EthernetPacket::new(packet).unwrap();
                        if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                                let src = header.get_source().to_string();
                                let dst = header.get_destination().to_string();
                                
                                // Se bater com o filtro (origem ou destino), incrementa a linha amarela
                                if &src == target_ip || &dst == target_ip {
                                    filtered_count += 1;
                                }
                            }
                        }
                    } else {
                        // Se não tem filtro definido, a linha amarela é igual à total (ou 0, sua escolha)
                        // Geralmente visualizadores mostram igual ou ocultam. 
                        // Vamos assumir igual para simplificar, ou 0 se quiser esconder.
                        filtered_count += 1; 
                    }
                }
                Err(_) => continue,
            }
        }
    });

    Ok(())
}
// --- Module Registration ---
#[pymodule]
fn pynetsketch_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rust_scan_ports, m)?)?;
    m.add_function(wrap_pyfunction!(rust_tcp_ping, m)?)?;
    m.add_function(wrap_pyfunction!(rust_subnet_sweep, m)?)?;
    m.add_function(wrap_pyfunction!(start_sniffer, m)?)?;
    Ok(())
}