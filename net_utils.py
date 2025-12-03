import sys
import platform
import subprocess
import socket
import ipaddress
import time
import requests
import re
from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr1, conf, sniff
import utils

# --- IMPORT RUST CORE ---
try:
    import pynetsketch_core
    RUST_AVAILABLE = True
    print("SUCCESS: Rust acceleration module loaded.")
except ImportError as e:
    RUST_AVAILABLE = False
    print(f"WARNING: Could not load Rust module ({e}). Running in legacy Python mode.")

# Suppress Scapy verbosity
conf.verb = 0

# Cache to avoid hitting API rate limits
VENDOR_CACHE = {}

def get_os_type():
    return platform.system()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def tcp_ping(target_ip, port=80, timeout=1):
    """Performs a TCP SYN ping (Connect)."""
    # Use Rust if available for potentially lower overhead, though single ping is fast in Py too
    if RUST_AVAILABLE:
        try:
            is_open, latency = pynetsketch_core.rust_tcp_ping(target_ip, port, int(timeout*1000))
            return is_open, latency
        except Exception:
            pass # Fallback to python

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.perf_counter()
        result = sock.connect_ex((target_ip, port))
        end_time = time.perf_counter()
        sock.close()
        
        if result == 0:
            duration_ms = (end_time - start_time) * 1000
            return True, duration_ms
        return False, 0
    except:
        return False, 0

def ping_host(target_ip, stop_event=None, progress_callback=None):
    """Pings a host. Tries ICMP first, then falls back to TCP Ping."""
    if stop_event and stop_event.is_set(): return False, 0
    
    os_type = get_os_type()
    param = '-n' if os_type.lower() == 'windows' else '-c'
    command = ['ping', param, '1', target_ip]
    
    utils._log_operation(f"ICMP Pinging {target_ip}...")
    
    icmp_success = False
    duration_ms = 0
    
    try:
        start_time = time.perf_counter()
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            timeout=2 
        )
        end_time = time.perf_counter()
        
        if result.returncode == 0:
            icmp_success = True
            match = re.search(r"time[=<]([\d\.]+)", result.stdout, re.IGNORECASE)
            if match:
                duration_ms = float(match.group(1))
            else:
                duration_ms = (end_time - start_time) * 1000
    except Exception:
        pass

    if icmp_success:
        return True, round(duration_ms, 2)
    
    if progress_callback: progress_callback("ICMP failed. Trying TCP Ping fallback...")
    utils._log_operation(f"ICMP failed for {target_ip}. Trying TCP probes...")
    
    fallback_ports = [80, 443, 53, 853]
    
    for port in fallback_ports:
        if stop_event and stop_event.is_set(): break
        success, rtt = tcp_ping(target_ip, port)
        if success:
            msg = f"TCP:{port} Success"
            utils._log_operation(msg)
            return True, rtt
            
    return False, 0

def resolve_mac_vendor(mac_address):
    mac = mac_address.upper()
    if len(mac) > 1 and mac[1] in ['2', '6', 'A', 'E']:
        return "Randomized / Virtual (LAA)"
    if mac in VENDOR_CACHE:
        return VENDOR_CACHE[mac]
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=1.5)
        if response.status_code == 200:
            vendor = response.text.strip()
            VENDOR_CACHE[mac] = vendor
            time.sleep(0.5) 
            return vendor
        elif response.status_code == 429:
            return "Too Many Requests (API Limit)"
        else:
            prefix = mac[:8]
            return conf.manufdb.get(prefix) or "Unknown Vendor"
    except Exception as e:
        prefix = mac[:8]
        return conf.manufdb.get(prefix) or "Unknown Vendor"

def arp_scan(network_cidr, stop_event=None, progress_callback=None):
    all_devices = []
    target_subnets = _parse_target_input(network_cidr)
    utils._log_operation(f"Processing scan targets: {target_subnets}")

    for subnet in target_subnets:
        if stop_event and stop_event.is_set(): break
        try:
            target_ip_base = subnet.split('/')[0]
            route = conf.route.route(target_ip_base)
            active_iface = route[0]
            
            if progress_callback: progress_callback(f"Scanning {subnet} via {active_iface}")
            
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            start_t = time.perf_counter()
            result = srp(packet, timeout=2, verbose=0, iface=active_iface)[0]
            duration = (time.perf_counter() - start_t) * 1000
            
            for sent, received in result:
                if stop_event and stop_event.is_set(): break
                if not any(d['ip'] == received.psrc for d in all_devices):
                    mac_addr = received.hwsrc
                    vendor_str = resolve_mac_vendor(mac_addr)
                    all_devices.append({'ip': received.psrc, 'mac': mac_addr, 'vendor': vendor_str})
            
            msg = f"Finished {subnet} in {duration:.0f}ms. Found {len(all_devices)} devices."
            utils._log_operation(msg)
            if progress_callback: progress_callback(msg)
        except Exception as e:
            utils._log_operation(f"Scan failed for {subnet}: {e}", "ERROR")
            continue
    return all_devices

def _parse_target_input(input_str):
    targets = []
    input_str = input_str.strip()
    if '-' in input_str:
        try:
            parts = input_str.split('-')
            if len(parts) == 2:
                start_net = ipaddress.ip_network(parts[0].strip(), strict=False)
                end_net = ipaddress.ip_network(parts[1].strip(), strict=False)
                if start_net.prefixlen != end_net.prefixlen: return [input_str]
                current_net_int = int(start_net.network_address)
                end_net_int = int(end_net.network_address)
                step = start_net.num_addresses
                while current_net_int <= end_net_int:
                    net_obj = ipaddress.ip_network((current_net_int, start_net.prefixlen), strict=False)
                    targets.append(str(net_obj))
                    current_net_int += step
                return targets
        except Exception: return [input_str]
    return [input_str]

def perform_traceroute(target_ip, max_hops=30, stop_event=None, progress_callback=None, resolve_dns=True):
    try:
        hops = []
        consecutive_timeouts = [] 
        utils._log_operation(f"Determining best trace method for {target_ip}...")
        if progress_callback: progress_callback(f"Probing {target_ip}...")

        methods = [
            ("ICMP", lambda t: IP(dst=target_ip, ttl=t)/ICMP()),
            ("TCP:80", lambda t: IP(dst=target_ip, ttl=t)/TCP(dport=80, flags="S")),
            ("TCP:53", lambda t: IP(dst=target_ip, ttl=t)/TCP(dport=53, flags="S")),
        ]
        
        selected_method_name = "TCP:80 (Fallback)" 
        packet_generator = methods[1][1]

        for name, generator in methods:
            if stop_event and stop_event.is_set(): return []
            try:
                pkt = generator(64) 
                resp = sr1(pkt, verbose=0, timeout=1.0)
                if resp:
                    selected_method_name = name
                    packet_generator = generator
                    break
            except Exception: continue

        utils._log_operation(f"Tracing using {selected_method_name}")
        
        for ttl in range(1, max_hops + 1):
            if stop_event and stop_event.is_set(): break
            pkt = packet_generator(ttl)
            start_t = time.perf_counter()
            reply = sr1(pkt, verbose=0, timeout=1)
            rtt_ms = (time.perf_counter() - start_t) * 1000
            
            hop_data = {'ttl': ttl, 'time': rtt_ms}
            
            if reply is None:
                consecutive_timeouts.append(ttl)
                hop_data.update({'ip': '*', 'hostname': ''})
                if progress_callback: progress_callback(f"Hop {ttl}: * Request timed out ({rtt_ms:.1f}ms)")
                hops.append(hop_data)
            else:
                if consecutive_timeouts:
                    for hidden_ttl in consecutive_timeouts:
                        msg = f"    [Analysis] Hop {hidden_ttl} is likely a HIDDEN NODE (Firewall/CGNAT)"
                        utils._log_operation(msg, "INFO")
                        if progress_callback: progress_callback(msg)
                    consecutive_timeouts = [] # Reset once reported
 

                hostname = ""
                if resolve_dns:
                    try: hostname = socket.gethostbyaddr(reply.src)[0]
                    except Exception: pass 
                hop_data.update({'ip': reply.src, 'hostname': hostname})
                hops.append(hop_data)
                
                host_str = f" ({hostname})" if hostname else ""
                if progress_callback: progress_callback(f"Hop {ttl}: {reply.src}{host_str} - {rtt_ms:.1f}ms")
                if reply.src == target_ip: break
        return hops
    except Exception as e:
        utils._log_operation(f"Traceroute failed: {e}", "ERROR")
        return []

def scan_ports(target_ip, ports=None, stop_event=None, progress_callback=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080]
    
    open_services = []
    utils._log_operation(f"Starting Port Scan on {target_ip}")
    
    # --- RUST IMPLEMENTATION ---
    if RUST_AVAILABLE:
        if progress_callback: progress_callback(f"[RUST] Scanning {len(ports)} ports on {target_ip}...")
        try:
            # Helper to pipe Rust logs to Python GUI
            def rust_logger_adapter(msg):
                utils._log_operation(msg)
                if progress_callback: progress_callback(msg)

            start_t = time.perf_counter()
            # Pass the logger callback to Rust
            open_ports_int = pynetsketch_core.rust_scan_ports(target_ip, ports, rust_logger_adapter)
            duration = (time.perf_counter() - start_t) * 1000
            
            for p in open_ports_int:
                open_services.append(f"[RUST] Port {p} OPEN")
                
            if progress_callback: progress_callback(f"Rust Scan finished in {duration:.2f}ms")
            return open_services
            
        except Exception as e:
            utils._log_operation(f"Rust scan failed ({e}). Falling back to Python.", "ERROR")
            # Fall through to Python implementation below
    
    # --- PYTHON FALLBACK IMPLEMENTATION ---
    if progress_callback: progress_callback(f"[PYTHON] Scanning {len(ports)} ports...")
    
    for i, port in enumerate(ports):
        if stop_event and stop_event.is_set():
            if progress_callback: progress_callback("Port scan stopped.")
            break
            
        # TCP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target_ip, port)) == 0:
                msg = f"[TCP] Port {port} OPEN"
                open_services.append(msg)
                if progress_callback: progress_callback(msg)
            sock.close()
        except: pass

        # UDP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(b'', (target_ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                msg = f"[UDP] Port {port} OPEN (Replied)"
                open_services.append(msg)
                if progress_callback: progress_callback(msg)
            except: pass
            sock.close()
        except: pass
    
    if progress_callback: progress_callback(f"Scan Complete. Found {len(open_services)} open services.")
    return open_services

def send_magic_packet(mac_address):
    try:
        mac_clean = mac_address.replace(":", "").replace("-", "")
        if len(mac_clean) != 12: return False, "Invalid MAC"
        data = bytes.fromhex("FF" * 6 + mac_clean * 16)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(data, ("255.255.255.255", 9))
        return True, "Magic packet sent."
    except Exception as e:
        return False, str(e)

def monitor_traffic(interface=None, stop_event=None, progress_callback=None):
    utils._log_operation("Starting Traffic Monitor...")
    if progress_callback: progress_callback("Initializing Sniffer...")
    try:
        while not (stop_event and stop_event.is_set()):
            start_t = time.time()
            packets = sniff(timeout=1, count=0)
            count = len(packets)
            duration = time.time() - start_t
            if duration < 0.1: duration = 1.0
            if progress_callback: progress_callback(count)
    except Exception as e:
        if progress_callback: progress_callback(f"Sniffer error: {e}")

def organize_scan_results_by_subnet(devices):
    subnets = {}
    for dev in devices:
        parts = dev['ip'].split('.')
        if len(parts) == 4:
            gw = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            if gw not in subnets: subnets[gw] = []
            subnets[gw].append(dev)
    return subnets