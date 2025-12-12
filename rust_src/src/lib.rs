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

/// Helper for Python
fn log_to_python(callback: &Py<PyAny>, message: String) {
    Python::with_gil(|py| {
        let _ = callback.call1(py, (message,));
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
                if TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(300)).is_ok() {
                    let msg = format!("[OPEN] Port {} (Detected by Rust)", port);
                    let cb_ref = Arc::clone(&callback_arc);
                    log_to_python(&cb_ref, msg);
                    Some(port)
                } else { None }
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
                    let start = Instant::now();
                    if TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(timeout_ms)).is_ok() {
                        let latency = start.elapsed().as_secs_f64() * 1000.0;
                        let msg = format!("Host {} is UP (Port {} - {:.2}ms) [Rust]", ip, port, latency);
                        log_to_python(&cb_outer, msg);
                        Some((ip.clone(), port, latency))
                    } else { None }
                })
            })
            .collect()
    })
}

// --- 4. Traffic Sniffer (Fixed Lifetimes) ---
// #[pyfunction]
// #[pyo3(signature = (callback, interface_name=None, filter_ip=None))]
// fn start_sniffer(
//     py: Python,
//     callback: PyObject,
//     interface_name: Option<String>,
//     filter_ip: Option<String>
// ) -> PyResult<()> {
    
//     // Setup Interface
//     let interfaces = datalink::interfaces();
//     let interface = match interface_name {
//         Some(name) => interfaces.into_iter().find(|iface| iface.name == name)
//                                 .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Interface not found"))?,
//         None => interfaces.into_iter().find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
//                                 .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("No suitable interface found"))?
//     };

//     // Timeout config to fix error where rust monitor would "refuse" to stop
//     let mut config = Config::default();
//     config.read_timeout = Some(Duration::from_millis(200)); // Wakes up each 200ms interval

//     let (_, mut rx) = match datalink::channel(&interface, config) { // Pass config here
//         Ok(Ethernet(tx, rx)) => (tx, rx),
//         Ok(_) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unhandled channel type")),
//         Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyOSError, _>(format!("Failed to create channel: {}", e))),
//     };

//     // Main loop
//     py.allow_threads(move || {
//         let mut total_count = 0;
//         let mut filtered_count = 0;
//         let mut last_report = Instant::now();

//         loop {
//             // Periodical cancel check
//             // Full second pass, reports and verifies if should stop
//             if last_report.elapsed() >= Duration::from_secs(1) {
//                 let t_pps = total_count;
//                 let f_pps = filtered_count;
//                 total_count = 0;
//                 filtered_count = 0;
//                 last_report = Instant::now();

//                 let should_continue = Python::with_gil(|py| {
//                     match callback.call1(py, ((t_pps, f_pps),)) {
//                         Ok(result) => result.extract::<bool>(py).unwrap_or(true),
//                         Err(_) => false 
//                     }
//                 });

//                 if !should_continue { break; }
//             }

//             // Read with Timeout
//             match rx.next() {
//                 Ok(packet) => {
//                     // ... (Lógica de processamento de pacote IDÊNTICA à anterior) ...
//                     total_count += 1;
//                     if let Some(ref target_ip) = filter_ip {
//                          if let Some(ethernet) = EthernetPacket::new(packet) {
//                             let is_match = match ethernet.get_ethertype() {
//                                 EtherTypes::Ipv4 => {
//                                     if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
//                                         let src = header.get_source().to_string();
//                                         let dst = header.get_destination().to_string();
//                                         src == *target_ip || dst == *target_ip
//                                     } else { false }
//                                 },
//                                 EtherTypes::Vlan => {
//                                      if let Some(vlan) = VlanPacket::new(ethernet.payload()) {
//                                         if vlan.get_ethertype() == EtherTypes::Ipv4 {
//                                             if let Some(header) = Ipv4Packet::new(vlan.payload()) {
//                                                 let src = header.get_source().to_string();
//                                                 let dst = header.get_destination().to_string();
//                                                 src == *target_ip || dst == *target_ip
//                                             } else { false }
//                                         } else { false }
//                                     } else { false }
//                                 },
//                                 _ => false
//                             };
//                             if is_match { filtered_count += 1; }
//                          }
//                     } else {
//                         filtered_count += 1;
//                     }
//                 },
//                 Err(e) => {
//                     // Timeout is normal. Ignore and loop runs again
//                     // Allows for "should_continue" up there to run.
//                     match e.kind() {
//                         std::io::ErrorKind::TimedOut => continue,
//                         _ => continue, // Ignore other errors
//                     }
//                 }
//             }
//         }
//     });

//     Ok(())
// }
#[pyfunction]
#[pyo3(signature = (callback, interface_name=None, filter_ip=None))]
fn start_sniffer(
    py: Python,
    callback: PyObject,
    interface_name: Option<String>,
    filter_ip: Option<String>
) -> PyResult<()> {
    
    println!("DEBUG [Rust]: Iniciando Sniffer..."); // DEBUG

    let interfaces = datalink::interfaces();
    let interface = match interface_name {
        Some(name) => interfaces.into_iter().find(|iface| iface.name == name)
                                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Interface not found"))?,
        None => interfaces.into_iter().find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
                                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("No suitable interface found"))?
    };

    println!("DEBUG [Rust]: Interface selecionada: {}", interface.name); // DEBUG

    // TENTATIVA DE TIMEOUT MAIS AGRESSIVO (100ms)
    let mut config = Config::default();
    config.read_timeout = Some(Duration::from_millis(100));

    let (_, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unhandled channel type")),
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyOSError, _>(format!("Failed to create channel: {}", e))),
    };

    println!("DEBUG [Rust]: Canal aberto. Entrando no loop de threads..."); // DEBUG

    py.allow_threads(move || {
        let mut total_count = 0;
        let mut filtered_count = 0;
        let mut last_report = Instant::now();
        let mut loops_without_packets = 0; // Contador de ciclos ociosos

        loop {
            // A. CHECK DE CANCELAMENTO (A cada 1s)
            if last_report.elapsed() >= Duration::from_secs(1) {
                // println!("DEBUG [Rust]: 1 segundo passou. Reportando ao Python..."); // DEBUG (Comente se for muito spam)

                let t_pps = total_count;
                let f_pps = filtered_count;
                total_count = 0;
                filtered_count = 0;
                last_report = Instant::now();

                // PERGUNTA AO PYTHON: "DEVO PARAR?"
                let should_continue = Python::with_gil(|py| {
                    match callback.call1(py, ((t_pps, f_pps),)) {
                        Ok(result) => {
                            let res = result.extract::<bool>(py).unwrap_or(true);
                            if !res {
                                println!("DEBUG [Rust]: Python retornou FALSE (Pare!)"); // DEBUG CRÍTICO
                            }
                            res
                        },
                        Err(e) => {
                            println!("DEBUG [Rust]: Erro ao chamar callback: {}", e);
                            false // Para se der erro
                        }
                    }
                });

                if !should_continue {
                    println!("DEBUG [Rust]: Recebi ordem de parada. Saindo do loop..."); // DEBUG CRÍTICO
                    break;
                }
            }

            // B. LEITURA DE PACOTES
            match rx.next() {
                Ok(packet) => {
                    loops_without_packets = 0; // Reset
                    total_count += 1;
                    // ... (Lógica de processamento de pacotes e VLAN omitida para brevidade, mantenha a sua aqui) ...
                    // Apenas para teste, vamos ignorar a lógica complexa de VLAN aqui e focar no loop
                    if let Some(ref target_ip) = filter_ip {
                        // (Mantenha sua lógica de filtro aqui)
                    } else {
                        filtered_count += 1;
                    }
                },
                Err(e) => {
                    match e.kind() {
                        ErrorKind::TimedOut => {
                            loops_without_packets += 1;
                            // Imprime um pontinho a cada 10 timeouts (1 seg) para mostrar que está vivo
                            if loops_without_packets % 10 == 0 {
                                // print!("."); // Mostra que a thread não travou
                                // use std::io::Write;
                                // std::io::stdout().flush().unwrap();
                            }
                            continue;
                        },
                        _ => {
                            println!("DEBUG [Rust]: Erro de leitura diferente de timeout: {}", e);
                            continue;
                        }
                    }
                }
            }
        }
        println!("DEBUG [Rust]: Loop finalizado. Thread encerrando.");
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