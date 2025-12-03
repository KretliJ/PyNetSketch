use pyo3::prelude::*;
use std::net::TcpStream;
use std::time::{Duration, Instant};
use rayon::prelude::*; // Parallel iteration
use std::sync::Arc; // Import Arc for thread-safe reference counting

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
    // Wrap callback in Arc to guarantee thread-safe cloning
    let callback_arc = Arc::new(callback);

    // Release GIL for parallelism
    py.allow_threads(|| {
        ports.par_iter()
            .filter_map(|&port| {
                let address = format!("{}:{}", ip, port);
                // Fast timeout (300ms)
                if TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(300)).is_ok() {
                    // Found open port -> Log immediately
                    let msg = format!("[OPEN] Port {} (Detected by Rust)", port);
                    
                    // Clone the Arc, which is cheap and always implemented
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
    // Wrap callback in Arc
    let callback_arc = Arc::new(callback);

    py.allow_threads(|| {
        ips.par_iter()
            .flat_map(|ip| {
                // Clone Arc for the outer loop
                let cb_outer = Arc::clone(&callback_arc);
                
                ports.par_iter().filter_map(move |&port| {
                    let address = format!("{}:{}", ip, port);
                    let start = Instant::now();
                    
                    if TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(timeout_ms)).is_ok() {
                        let latency = start.elapsed().as_secs_f64() * 1000.0;
                        
                        let msg = format!("Host {} is UP (Port {} - {:.2}ms) [Rust]", ip, port, latency);
                        // Clone Arc for the inner call
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

// --- Module Registration ---
#[pymodule]
fn pynetsketch_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(rust_scan_ports, m)?)?;
    m.add_function(wrap_pyfunction!(rust_tcp_ping, m)?)?;
    m.add_function(wrap_pyfunction!(rust_subnet_sweep, m)?)?;
    Ok(())
}