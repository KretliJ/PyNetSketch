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
import traceback
    
# --- IMPORT RUST CORE ---
# This is important for python implementation fallback
# Application will be slower, but shouldn't crash
try:
    import pynetsketch_core
    print(f"DEBUG: Loaded Rust module from: {pynetsketch_core.__file__}") # <--- ADD THIS
    print(f"DEBUG: Available functions: {dir(pynetsketch_core)}")          # <--- ADD THIS
    RUST_AVAILABLE = True
    print("SUCCESS: Rust acceleration module loaded.")
except ImportError as e:
    RUST_AVAILABLE = False
    print(f"WARNING: Could not load Rust module ({e}). Running in legacy Python mode.")

# Suppress Scapy verbosity
conf.verb = 0

# MAC Vendor cache
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
    # Performs a TCP SYN ping (Connect).
    # Where it starts to look toward lowering overhead
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
    # Pings a host. Tries ICMP first, then falls back to TCP
    if stop_event and stop_event.is_set(): return False, 0
    
    os_type = get_os_type()
    param = '-n' if os_type.lower() == 'windows' else '-c'
    command = ['ping', param, '1', target_ip]
    
    utils._log_operation(f"ICMP Pinging {target_ip}...")
    
    icmp_success = False
    duration_ms = 0
    
    try:
        # Most operations will count time
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
    # Many operations call writing to text log for debug
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

# Resolve the manufacturer of a device via macvendors API to show in relevant modes
# Returns vendor if found. If not, assumes MAC is randomized (in a range) or returns Unknown if all else fails 
# This used to call for an API, but that causes issues when dealing with large networks
#   manufdb is faster with good enough identification capabilities
def resolve_mac_vendor(mac_address):
   # Checks DB was already marked as broken to prevent log floods
    if VENDOR_CACHE.get("scapy_db_broken", False):
        return "Unknown Vendor (DB Error)"

    mac = mac_address.upper()
    
    # Check for Locally Administered Addresses
    if len(mac) > 1 and mac[1] in ['2', '6', 'A', 'E']:
        return "Randomized / Virtual (LAA)"

    # Check local memory cache
    if mac in VENDOR_CACHE:
        return VENDOR_CACHE[mac]

    # Lookup in Scapy's internal database
    try:
        # Check existence
        if not hasattr(conf, "manufdb") or conf.manufdb is None:
            if not VENDOR_CACHE.get("scapy_db_broken"):
                utils._log_operation("Scapy 'manufdb' not initialized. Disabling lookup.", "WARN")
                VENDOR_CACHE["scapy_db_broken"] = True
            return "Unknown Vendor"

        prefix = mac[:8]
        
        # FIX: Scapy DADict often lacks .get(), use direct access with try/except
        try:
            vendor = conf.manufdb[prefix]
        except KeyError:
            vendor = None
        except AttributeError:
            # This catches the specific error from missing .get or getattr fail
            raise AttributeError("Manufdb object does not support access")

        if vendor:
            VENDOR_CACHE[mac] = vendor
            return vendor
            
    except AttributeError as e:
        # Specific DB crash. Log once, then disable.
        if not VENDOR_CACHE.get("scapy_db_broken"):
            utils._log_operation(f"Critical Scapy DB Failure: {e}. Disabling vendor resolution.", "ERROR")
            VENDOR_CACHE["scapy_db_broken"] = True
        return "Unknown Vendor"
        
    except Exception:
        # Catch-all for other weirdness, simplified logging
        # Don't log this anymore to keep logs clean unless it's an unique future error
        # TODO: Fix this when unit testing is implemented
        pass

    return "Unknown Vendor"

# Main function for python ARP table scan
# This isn't handled by rust since the added complexity did not justify possible performance gains at the time
# Existing rust implementations exist. Maybe look for a third party module?
# Returns list with found devices in provided range
def arp_scan(network_cidr, stop_event=None, progress_callback=None):
    all_devices = []
    # Parse input to ensure we have valid networks
    target_subnets = _parse_target_input(network_cidr)
    
    utils._log_operation(f"Processing scan targets: {target_subnets}")

    for subnet_str in target_subnets:
        if stop_event and stop_event.is_set(): break
        
        try:
            # String to network object
            network = ipaddress.ip_network(subnet_str, strict=False)
            
            # --- CHUNKING LOGIC ---
            # For nets bigger than /24 (256+ hosts), breaks in /24 subnets
            if network.prefixlen < 24:
                utils._log_operation(f"Large subnet detected ({subnet_str}). Chunking into /24 blocks...")
                chunks = list(network.subnets(new_prefix=24))
            else:
                chunks = [network]
            
            total_chunks = len(chunks)
            
            for i, chunk in enumerate(chunks):
                # Verifies STOP each 256 IPs bloc
                if stop_event and stop_event.is_set():
                    utils._log_operation("Scan aborted by user during chunking.")
                    return all_devices

                chunk_str = str(chunk)
                if progress_callback: 
                    progress_callback(f"Scanning chunk {i+1}/{total_chunks}: {chunk_str}")

                # Original Scapy logic (now operating on current chunk)
                target_ip_base = chunk_str.split('/')[0]
                route = conf.route.route(target_ip_base)
                active_iface = route[0]
                
                arp = ARP(pdst=chunk_str)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                
                # Short timeout per chunk keeps loop agility
                result = srp(packet, timeout=1.5, verbose=0, iface=active_iface)[0]
                
                for sent, received in result:
                    if not any(d['ip'] == received.psrc for d in all_devices):
                        mac_addr = received.hwsrc
                        vendor_str = resolve_mac_vendor(mac_addr)
                        all_devices.append({'ip': received.psrc, 'mac': mac_addr, 'vendor': vendor_str})
                
                # Uncomment short pause for GUI if needed for massive networks
                # time.sleep(0.01) 

            msg = f"Finished scanning {subnet_str}. Total devices: {len(all_devices)}"
            utils._log_operation(msg)
            
        except Exception as e:
            utils._log_operation(f"Scan failed for {subnet_str}: {e}", "ERROR")
            continue
            
    return all_devices

# Parsing of range start and end for use by arp_scan()
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

# Rust implementation avoided for same reason as above
# Has proven faster than windows' native tracert whether DNS resolving is true or false (TODO: Testing comparisons)
# Returns list of hops
def perform_traceroute(target_ip, max_hops=30, stop_event=None, progress_callback=None, resolve_dns=True):
    try:
        # Tries to determine best method for trace (Fallback on failure)
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

        # Generates packets based on chosen method
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
        
        # Sends requests iteratively up to the last hop (breaks up to max if final isn't found)
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
                    # This analyzes the possibility that an unresponsive node might be online but simply not responding 
                    for hidden_ttl in consecutive_timeouts:
                        msg = f"    [Analysis] Hop {hidden_ttl} is likely a HIDDEN NODE (Firewall/CGNAT)"
                        utils._log_operation(msg, "INFO")
                        if progress_callback: progress_callback(msg)
                    consecutive_timeouts = [] # Reset once reported
 

                hostname = ""
                # DNS resolution section if applicable
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

# Port scanning from rust with fallback to python. 
# Returns list with open ports
def scan_ports(target_ip, ports=None, stop_event=None, progress_callback=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080]
    
    open_services = []
    utils._log_operation(f"Starting Port Scan on {target_ip}")
    
    # --- RUST IMPLEMENTATION ---
    if RUST_AVAILABLE:
        if progress_callback: progress_callback(f"[RUST] Scanning {len(ports)} ports on {target_ip}...")
        try:
            # Helper pipes Rust logs to Python GUI
            def rust_logger_adapter(msg):
                utils._log_operation(msg)
                if progress_callback: progress_callback(msg)

            start_t = time.perf_counter()
            # Pass logger callback to Rust
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
    
    # Iterates through ports to scan
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

# Simple function that attempts to send a Wake-On-Lan packet to selected mac address
# Returns success or failure
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

def monitor_traffic(interface=None, filter_ip=None, stop_event=None, progress_callback=None):
    utils._log_operation(f"Starting Traffic Monitor (Filter: {filter_ip if filter_ip else 'None'})...")
    
    # 1. SELEÇÃO INTELIGENTE DE INTERFACE
    if interface is None:
        try:
            route = conf.route.route("8.8.8.8")
            active_iface = route[0]
            target_interface_name = active_iface.name
            utils._log_operation(f"Auto-detected active internet interface: {target_interface_name}")
        except Exception:
            if not conf.iface: conf.route.route("8.8.8.8")
            target_interface_name = conf.iface.name
    else:
        target_interface_name = interface

    # --- RUST IMPLEMENTATION (PNET) ---
    if RUST_AVAILABLE:
        try:
            # 2. MATCHING DE GUID (O Pulo do Gato)
            rust_ifaces = pynetsketch_core.rust_list_interfaces()
            
            if target_interface_name not in rust_ifaces:
                found_match = None
                
                # --- NOVO BLOCO DE RESOLUÇÃO (Windows Specific) ---
                if platform.system() == "Windows":
                    try:
                        from scapy.arch.windows import get_windows_if_list
                        win_ifaces = get_windows_if_list()
                        target_guid = None
                        
                        for iface_dict in win_ifaces:
                            if iface_dict['name'].strip().lower() == target_interface_name.strip().lower():
                                target_guid = iface_dict['guid']
                                break
                        
                        if target_guid:
                            clean_target = target_guid.upper().replace("{", "").replace("}", "")
                            for r_iface in rust_ifaces:
                                clean_rust = r_iface.upper().replace("{", "").replace("}", "")
                                if clean_target in clean_rust:
                                    found_match = r_iface
                                    utils._log_operation(f"SUCCESS: Mapped '{target_interface_name}' -> '{found_match}'")
                                    break
                    except Exception as e:
                        utils._log_operation(f"Translation Error: {e}", "ERROR")
                # --- FIM DO NOVO BLOCO ---

                if found_match:
                    target_interface_name = found_match
                else:
                    utils._log_operation(f"WARNING: Could not map '{target_interface_name}' to Rust device. Using raw name.", "WARN")
            
            # 3. Definição do Callback
            def bridge_callback(stats):
                if progress_callback: progress_callback(stats)
                if stop_event and stop_event.is_set(): return False
                return True

            pynetsketch_core.start_sniffer(bridge_callback, target_interface_name, filter_ip)
            return

        except Exception as e:
            utils._log_operation(f"Rust sniffer failed: {e}. Falling back to Scapy.", "ERROR")    
    
    # --- PYTHON FALLBACK (SCAPY) ---
    if progress_callback: progress_callback("Initializing Scapy Sniffer (Slow Mode)...")
    try:
        # Loop principal do modo lento
        while not (stop_event and stop_event.is_set()):
            total_count = 0
            filtered_count = 0
            
            # Dicionário local para contar IPs neste segundo
            # Estrutura: { "192.168.1.5": 10, ... }
            ip_counts = {} 

            def count_pkt(p):
                nonlocal total_count, filtered_count
                total_count += 1
                
                # Verifica se é pacote IP para extrair origem
                if IP in p:
                    src_ip = p[IP].src
                    
                    # 1. Incrementa contagem do IP
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                    
                    # 2. Lógica de Filtro
                    if filter_ip:
                        if src_ip == filter_ip or p[IP].dst == filter_ip:
                            filtered_count += 1
                    else:
                        filtered_count += 1
                else:
                    # Pacotes não-IP (ARP, IPv6 puro, etc) contam no total mas não entram na lista de IPs
                    # Se não houver filtro, contam como 'passed'
                    if not filter_ip:
                        filtered_count += 1

            # Escuta por 1 segundo (bloqueante)
            sniff(prn=count_pkt, timeout=1, store=0)
            
            # Transforma o dict em lista de tuplas e ordena: [('192.168.1.5', 10), ...]
            top_ips = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)
            
            # Envia a tupla de 3 elementos, igual ao Rust
            if progress_callback: 
                progress_callback((total_count, filtered_count, top_ips))
            
    except Exception as e:
        utils._log_operation(f"Sniffer error: {e}", "ERROR")
        if progress_callback: progress_callback(f"Sniffer error: {e}")
        
# Function to organize the results of ARP table scans and group them by subnets
# Returns a dictionary where keys are Gateway IPs as strings and values are lists of device dictionaries belonging to that subnet.
def organize_scan_results_by_subnet(devices):
    subnets = {}
    
    # Defines default mask if not given
    DEFAULT_MASK = "/24" 
    
    # Group by Network ID (X.Y.Z.0)
    grouped_by_net_id = {}
    for dev in devices:
        ip_addr = dev['ip']
        try:
            # Creates an IP network object from device's and mask's IP
            network_id = str(ipaddress.ip_network(f"{ip_addr}{DEFAULT_MASK}", strict=False).network_address)
            
            if network_id not in grouped_by_net_id: 
                grouped_by_net_id[network_id] = []
            
            # Store IP for futher analysis
            grouped_by_net_id[network_id].append(ip_addr)
            
        except ValueError:
            # Ignores invalid IPs (e.g.: 0.0.0.0 or 127.0.0.1)
            continue 

    # Determine cluster ID (main node)
    # This version consider cluster ID as lowest valid IP found in subnet (.1, .2, etc.)
    for network_id, ip_list in grouped_by_net_id.items():
        # IPs to integer to find smallest
        ip_ints = []
        for ip_str in ip_list:
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                # Verifies if IP is not Network ID (.0) or Broadcast (.255)
                if ip_obj != ipaddress.ip_network(f"{network_id}{DEFAULT_MASK}").network_address and \
                   ip_obj != ipaddress.ip_network(f"{network_id}{DEFAULT_MASK}").broadcast_address:
                    ip_ints.append(int(ip_obj))
            except ValueError:
                continue

        if ip_ints:
            # Selects IP with lowest value (Closest from .1m or .1 itself)
            lowest_ip_int = min(ip_ints)
            cluster_ip = str(ipaddress.IPv4Address(lowest_ip_int))
        else:
            # Fallback: No valid IPs, use network address as identifier
            cluster_ip = network_id 
        
        # Group final devices using new Cluster ID
        subnets[cluster_ip] = [dev for dev in devices if dev['ip'] in ip_list]
            
    return subnets