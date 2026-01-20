import sys
import platform
import subprocess
import socket
import ipaddress
import time
import threading
import re
from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr1, conf, sniff
import utils
import traceback
import requests

# --- IMPORT RUST CORE ---
try:
    import pynetsketch_core
    # print(f"DEBUG: Loaded Rust module from: {pynetsketch_core.__file__}")
    RUST_AVAILABLE = True
    # print("SUCCESS: Rust acceleration module loaded.")
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

# --- HELPER: FAST DNS RESOLVER ---
def _resolve_hostname_fast(ip_addr, timeout=0.5):
    """
    Resolve DNS em uma thread separada para garantir timeout real,
    evitando que a GUI trave esperando o SO.
    """
    result = [None]
    def target():
        try:
            result[0] = socket.gethostbyaddr(ip_addr)[0]
        except Exception:
            pass

    t = threading.Thread(target=target)
    t.daemon = True
    t.start()
    t.join(timeout)
    return result[0] if result[0] else ""

def tcp_ping(target_ip, port=80, timeout=1):
    # Performs a TCP SYN ping (Connect).
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
    # Verifica stop imediatamente
    if stop_event and stop_event.is_set(): return False, 0
    
    os_type = get_os_type()
    param = '-n' if os_type.lower() == 'windows' else '-c'
    
    # Flags para ocultar janela no Windows
    startupinfo = None
    if os_type.lower() == 'windows':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    
    command = ['ping', param, '1', target_ip]
    if os_type.lower() != 'windows':
        command.extend(['-W', '2']) 

    utils._log_operation(f"ICMP Pinging {target_ip}...")
    
    icmp_success = False
    duration_ms = 0
    
    try:
        start_time = time.perf_counter()
        
        # --- MUDANÇA: USAR POPEN AO INVÉS DE RUN ---
        # Isso permite verificar o stop_event ENQUANTO o ping roda
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            startupinfo=startupinfo
        )
        
        while process.poll() is None:
            # Verifica a cada 0.1s se o usuário pediu para parar
            if stop_event and stop_event.is_set():
                process.kill()  # Mata o processo do SO imediatamente
                return False, 0
            time.sleep(0.1)
            
            # Timeout manual de segurança (2s)
            if (time.perf_counter() - start_time) > 2.0:
                process.kill()
                break

        # Captura a saída após o término
        stdout, _ = process.communicate()
        end_time = time.perf_counter()
        
        if process.returncode == 0:
            icmp_success = True
            match = re.search(r"time[=<]([\d\.]+)", stdout, re.IGNORECASE)
            if match:
                duration_ms = float(match.group(1))
            else:
                duration_ms = (end_time - start_time) * 1000
                
    except Exception:
        pass

    if icmp_success:
        return True, round(duration_ms, 2)
    
    # --- FALLBACK TCP ---
    # Se falhou ICMP, verifica se deve continuar antes de tentar TCP
    if stop_event and stop_event.is_set(): return False, 0

    if progress_callback: progress_callback("ICMP failed. Trying TCP Ping fallback...")
    utils._log_operation(f"ICMP failed for {target_ip}. Trying TCP probes...")
    
    fallback_ports = [80, 443, 53, 853]
    
    for port in fallback_ports:
        if stop_event and stop_event.is_set(): break
        
        # Timeout curto no TCP também ajuda na responsividade
        success, rtt = tcp_ping(target_ip, port, timeout=0.5)
        if success:
            msg = f"TCP:{port} Success"
            utils._log_operation(msg)
            return True, rtt
            
    return False, 0

def resolve_mac_vendor(mac_address):
    if VENDOR_CACHE.get("scapy_db_broken", False):
        return "Unknown Vendor (DB Error)"

    mac = mac_address.upper()
    if len(mac) > 1 and mac[1] in ['2', '6', 'A', 'E']:
        return "Randomized / Virtual (LAA)"

    if mac in VENDOR_CACHE:
        return VENDOR_CACHE[mac]

    try:
        if not hasattr(conf, "manufdb") or conf.manufdb is None:
            if not VENDOR_CACHE.get("scapy_db_broken"):
                utils._log_operation("Scapy 'manufdb' not initialized.", "WARN")
                VENDOR_CACHE["scapy_db_broken"] = True
            return "Unknown Vendor"

        prefix = mac[:8]
        try:
            vendor = conf.manufdb[prefix]
        except (KeyError, AttributeError):
            vendor = None

        if vendor:
            VENDOR_CACHE[mac] = vendor
            return vendor
            
    except Exception:
        pass

    return "Unknown Vendor"

def get_ip_location(ip_addr):
    if not ip_addr or ip_addr.startswith(("192.168.", "10.", "172.16.")):
        return None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=status,country,city,lat,lon", timeout=1.5)
        data = response.json()
        if data.get("status") == "success":
            print(f"DEBUG [GeoIP]: {ip_addr} -> {data['city']}, {data['country']} ({data['lat']}, {data['lon']})")
            return {
                "display": f" [{data['city']}, {data['country']}]",
                "lat": data["lat"],
                "lon": data["lon"]
            }
        else:
            print(f"DEBUG [GeoIP]: Falha para o IP {ip_addr}")
    except Exception as e:
        print(f"DEBUG [GeoIP]: Erro na requisição: {e}")
    return None

def arp_scan(network_cidr, stop_event=None, progress_callback=None):
    all_devices = []
    target_subnets = _parse_target_input(network_cidr)
    
    utils._log_operation(f"Processing scan targets: {target_subnets}")

    for subnet_str in target_subnets:
        if stop_event and stop_event.is_set(): break
        
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            
            if network.prefixlen < 24:
                utils._log_operation(f"Large subnet detected ({subnet_str}). Chunking...")
                chunks = list(network.subnets(new_prefix=24))
            else:
                chunks = [network]
            
            total_chunks = len(chunks)
            
            for i, chunk in enumerate(chunks):
                if stop_event and stop_event.is_set():
                    utils._log_operation("Scan aborted by user.")
                    return all_devices

                chunk_str = str(chunk)
                if progress_callback: 
                    progress_callback(f"Scanning chunk {i+1}/{total_chunks}: {chunk_str}")

                target_ip_base = chunk_str.split('/')[0]
                route = conf.route.route(target_ip_base)
                active_iface = route[0]
                
                arp = ARP(pdst=chunk_str)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                
                # Timeout curto para manter agilidade
                result = srp(packet, timeout=1.5, verbose=0, iface=active_iface)[0]
                
                for sent, received in result:
                    if stop_event and stop_event.is_set(): break # Check intra-loop

                    if not any(d['ip'] == received.psrc for d in all_devices):
                        mac_addr = received.hwsrc
                        vendor_str = resolve_mac_vendor(mac_addr)
                        
                        # --- CORREÇÃO: Feedback imediato no console ---
                        if progress_callback:
                            progress_callback(f"[+] Found: {received.psrc} ({vendor_str})")
                        
                        all_devices.append({'ip': received.psrc, 'mac': mac_addr, 'vendor': vendor_str})
                
        except Exception as e:
            utils._log_operation(f"Scan failed for {subnet_str}: {e}", "ERROR")
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
        utils._log_operation(f"Tracing route to {target_ip}...")
        
        if progress_callback: progress_callback(f"Target: {target_ip} (Max Hops: {max_hops})")

        # Seleção de método (simplificada para agilidade)
        methods = [
            ("ICMP", lambda t: IP(dst=target_ip, ttl=t)/ICMP()),
            ("TCP:80", lambda t: IP(dst=target_ip, ttl=t)/TCP(dport=80, flags="S"))
        ]
        
        packet_generator = methods[0][1] # Padrão ICMP
        
        # Teste rápido de conectividade inicial
        if not stop_event or not stop_event.is_set():
             try:
                 test_pkt = packet_generator(64)
                 sr1(test_pkt, verbose=0, timeout=1.0)
             except: pass

        for ttl in range(1, max_hops + 1):
            if stop_event and stop_event.is_set(): 
                break
            
            reply = None
            rtt_ms = 0
            
            # --- LÓGICA DE DETECÇÃO DE NÓS OCULTOS ---
            # Tenta o método primário (ICMP) e, se falhar, tenta o secundário (TCP)
            for method_name, generator in methods:
                pkt = generator(ttl)
                start_t = time.perf_counter()
                reply = sr1(pkt, verbose=0, timeout=1.2) # Timeout ajustado para retentativas
                rtt_ms = (time.perf_counter() - start_t) * 1000
                
                if reply is not None:
                    # Se o nó foi revelado apenas pelo segundo método, logamos o evento
                    if method_name != "ICMP":
                        utils._log_operation(f"Hidden node revealed at hop {ttl} using {method_name}")
                    break 
            # ------------------------------------------

            hop_data = {'ttl': ttl, 'time': rtt_ms}
            
            if reply is None:
                # Se todos os métodos falharem, continua como timeout
                consecutive_timeouts.append(ttl)
                hop_data.update({'ip': '*', 'hostname': ''})
                if progress_callback: progress_callback(f"{ttl}\tRequest timed out. This might be a hidden node")
                hops.append(hop_data)
            else:
                hostname = ""
                location_data = None
                display_loc = ""

                if resolve_dns:
                    hostname = _resolve_hostname_fast(reply.src, timeout=0.5)
                    location_data = get_ip_location(reply.src) # Agora retorna dicionário

                # Monta os dados do salto para o mapa
                hop_info = {'ttl': ttl, 'time': rtt_ms, 'ip': reply.src, 'hostname': hostname}
                
                if location_data:
                    display_loc = location_data.get('display', '')
                    hop_info.update({
                        'lat': location_data.get('lat'),
                        'lon': location_data.get('lon'),
                        'display': display_loc
                    })

                hops.append(hop_info)
                
                # Feedback para o console (usando a string display_loc)
                host_display = f" ({hostname})" if hostname else ""
                msg = f"{ttl}\t{rtt_ms:.1f} ms\t{reply.src}{host_display}{display_loc}"
                if progress_callback: progress_callback(msg)
                
                if reply.src == target_ip:
                    if progress_callback: progress_callback("Trace complete.")
                    break
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
            def rust_logger_adapter(msg):
                utils._log_operation(msg)
                if progress_callback: progress_callback(msg)

            start_t = time.perf_counter()
            open_ports_int = pynetsketch_core.rust_scan_ports(target_ip, ports, rust_logger_adapter)
            duration = (time.perf_counter() - start_t) * 1000
            
            for p in open_ports_int:
                open_services.append(f"[RUST] Port {p} OPEN")
                
            if progress_callback: progress_callback(f"Rust Scan finished in {duration:.2f}ms")
            return open_services
            
        except Exception as e:
            utils._log_operation(f"Rust scan failed ({e}). Falling back to Python.", "ERROR")
    
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

def monitor_traffic(interface=None, filter_ip=None, stop_event=None, progress_callback=None):
    utils._log_operation(f"Starting Traffic Monitor (Filter: {filter_ip if filter_ip else 'None'})...")
    
    if interface is None:
        try:
            route = conf.route.route("8.8.8.8")
            iface_obj = route[0]
            # No Scapy, .name pode ser uma string ou um atributo
            target_interface_name = str(iface_obj.name) if hasattr(iface_obj, 'name') else str(iface_obj)
        except Exception:
            target_interface_name = str(conf.iface)
    else:
        target_interface_name = interface

    if RUST_AVAILABLE:
        try:
            rust_ifaces = pynetsketch_core.rust_list_interfaces()
            
            # Garante que estamos enviando a string correta para o Rust
            # Se o target_interface_name não estiver na lista do Rust, 
            # tentamos o mapeamento por GUID (essencial para Windows)
            actual_rust_name = target_interface_name
            
            if target_interface_name not in rust_ifaces:
                route = conf.route.route("8.8.8.8")
                scapy_iface = route[0]
                for riface in rust_ifaces:
                    if hasattr(scapy_iface, 'guid') and scapy_iface.guid and scapy_iface.guid in riface:
                        actual_rust_name = riface
                        break
            
            def bridge_callback(stats):
                if progress_callback: progress_callback(stats)
                return not (stop_event and stop_event.is_set())

            # Chamar o sniffer garantindo que o nome da interface seja String
            pynetsketch_core.start_sniffer(bridge_callback, str(actual_rust_name), filter_ip)
            return

        except Exception as e:
            utils._log_operation(f"Rust sniffer failed: {e}. Falling back to Scapy.", "ERROR")    
    
    if progress_callback: progress_callback("Initializing Scapy Sniffer (Slow Mode)...")
    try:
        while not (stop_event and stop_event.is_set()):
            total_count = 0
            filtered_count = 0
            ip_counts = {} 

            def count_pkt(p):
                nonlocal total_count, filtered_count
                total_count += 1
                if IP in p:
                    src_ip = p[IP].src
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                    if filter_ip:
                        if src_ip == filter_ip or p[IP].dst == filter_ip:
                            filtered_count += 1
                    else:
                        filtered_count += 1
                else:
                    if not filter_ip: filtered_count += 1

            sniff(prn=count_pkt, timeout=1, store=0)
            top_ips = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)
            
            if progress_callback: 
                progress_callback((total_count, filtered_count, top_ips))
            
    except Exception as e:
        utils._log_operation(f"Sniffer error: {e}", "ERROR")

def organize_scan_results_by_subnet(devices):
    subnets = {}
    DEFAULT_MASK = "/24" 
    grouped_by_net_id = {}
    for dev in devices:
        ip_addr = dev['ip']
        try:
            network_id = str(ipaddress.ip_network(f"{ip_addr}{DEFAULT_MASK}", strict=False).network_address)
            if network_id not in grouped_by_net_id: grouped_by_net_id[network_id] = []
            grouped_by_net_id[network_id].append(ip_addr)
        except ValueError: continue 

    for network_id, ip_list in grouped_by_net_id.items():
        subnets[network_id] = [dev for dev in devices if dev['ip'] in ip_list]
    return subnets