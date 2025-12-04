import socket
import threading
import json
import time
import os
import net_utils  # Your existing library
import utils      # To access LOG_FILE path

DISCOVERY_PORT = 5051  # UDP Port for discovery
CMD_PORT = 5050        # TCP Port for commands

class ProbeServer:
    def __init__(self, port=CMD_PORT, session_name="Unnamed Probe", log_callback=None):
        self.port = port
        self.session_name = session_name
        self.log_callback = log_callback
        self.running = False
        self.server_socket = None
        self.udp_socket = None # New UDP Socket
        self.active_connections = []

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)
        else:
            print(f"[SERVER LOG] {message}")

    def start(self):
        if self.running: return
        self.running = True

        # 1. Start TCP Command Server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.log(f"TCP Server listening on 0.0.0.0:{self.port}")
            
            threading.Thread(target=self._accept_loop, daemon=True).start()
            
            # 2. Start UDP Discovery Listener
            threading.Thread(target=self._discovery_loop, daemon=True).start()
            self.log("Discovery Service (UDP) started.")
            
        except Exception as e:
            self.log(f"Error starting server: {e}")
            self.running = False

    def stop(self):
        self.running = False
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
        if self.udp_socket:
            try: self.udp_socket.close()
            except: pass
        self.log("Server stopped.")

    def _discovery_loop(self):
        """Listens for 'PYNET_DISCOVER' broadcast messages."""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.bind(('0.0.0.0', DISCOVERY_PORT))

            while self.running:
                try:
                    data, addr = self.udp_socket.recvfrom(1024)
                    message = data.decode('utf-8').strip()
                    
                    if message == "PYNET_DISCOVER":
                        # Respond with our identity
                        response = json.dumps({
                            "session_name": self.session_name,
                            "ip": net_utils.get_local_ip(),
                            "port": self.port,
                            "type": "PyNetSketch Probe"
                        })
                        self.udp_socket.sendto(response.encode('utf-8'), addr)
                except Exception:
                    pass
        except Exception as e:
            self.log(f"Discovery Loop Error: {e}")

    def _accept_loop(self):
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                self.log(f"Client connected: {addr[0]}")
                t = threading.Thread(target=self._handle_client, args=(client, addr), daemon=True)
                t.start()
                self.active_connections.append(t)
            except OSError:
                break

    def _handle_client(self, client_sock, addr):
        # Stop event for this specific client session
        stop_event = threading.Event()
        
        try:
            client_sock.settimeout(None) # Blocking mode
            req = client_sock.recv(4096).decode('utf-8')
            if not req: return

            try:
                command = json.loads(req)
            except json.JSONDecodeError:
                return 

            action = command.get("action")
            self.log(f"Cmd '{action}' requested by {addr[0]}")

            # Special Handling for Traceroute (Streaming)
            if action == "traceroute":
                self._stream_traceroute(client_sock, command, stop_event)
                # Note: Socket closed after streaming finishes
            else:
                # Run command in a separate thread so we can monitor socket for disconnects?
                # For simplicity in this architecture, we pass stop_event to the command.
                # NOTE: Detecting disconnect reliably usually requires trying to read/write.
                # Since we are processing, we assume we are busy. 
                # If the user wants to stop, the mobile app closes the socket.
                # We can try to detect this write failure.
                
                response = self._process_command(command, stop_event)
                
                # Check if we should send response (might have been stopped)
                if not stop_event.is_set():
                    try:
                        client_sock.send(json.dumps(response).encode('utf-8'))
                    except (BrokenPipeError, ConnectionResetError):
                        self.log(f"Client {addr[0]} disconnected before response.")
                        stop_event.set()
                
        except Exception as e:
            self.log(f"Error handling client {addr[0]}: {e}")
            try:
                err_resp = {"status": "error", "message": str(e)}
                client_sock.send(json.dumps(err_resp).encode('utf-8'))
            except: pass
        finally:
            stop_event.set() # Ensure any background tasks know to stop
            try:
                client_sock.close()
            except: pass

    def _stream_traceroute(self, client_sock, command, stop_event):
        """
        Executes traceroute and streams partial results via socket.
        """
        target = command.get("target")
        resolve_dns = command.get("resolve_dns", True)
        
        # Currently standard execution returned as one block
        # To enable true streaming, net_utils would need a callback refactor
        # We pass stop_event so net_utils can abort if needed
        hops = net_utils.perform_traceroute(target, max_hops=15, stop_event=stop_event, resolve_dns=resolve_dns)
        
        if not stop_event.is_set():
            try:
                response = {"status": "ok", "result": hops}
                client_sock.send(json.dumps(response).encode('utf-8'))
            except:
                pass

    def _process_command(self, command, stop_event):
        action = command.get("action")
        target = command.get("target")

        if action == "identify":
            return {"status": "ok", "session_name": self.session_name, "version": "1.3"}
        
        elif action == "get_logs":
            try:
                log_path = utils.LOG_FILE
                if os.path.exists(log_path):
                    with open(log_path, "r", encoding="utf-8") as f:
                        f.seek(0, 2) 
                        size = f.tell()
                        f.seek(max(0, size - 2048), 0)
                        content = f.read()
                        return {"status": "ok", "logs": content}
                else:
                    return {"status": "ok", "logs": "No logs available."}
            except Exception as e:
                return {"status": "error", "message": f"Log read error: {e}"}

        elif action == "ping":
            success, rtt = net_utils.ping_host(target, stop_event=stop_event)
            return {"status": "ok", "result": {"online": success, "rtt": rtt}}

        elif action == "scan_ports":
            open_ports = net_utils.scan_ports(target, stop_event=stop_event)
            return {"status": "ok", "result": open_ports}
            
        elif action == "arp_scan":
            # Added handler for ARP Scan requested by mobile app
            # arp_scan returns a list of dicts: [{'ip':..., 'mac':..., 'vendor':...}]
            devices = net_utils.arp_scan(target, stop_event=stop_event)
            return {"status": "ok", "result": devices}

        elif action == "traceroute":
            resolve_dns = command.get("resolve_dns", True)
            hops = net_utils.perform_traceroute(target, max_hops=15, stop_event=stop_event, resolve_dns=resolve_dns)
            return {"status": "ok", "result": hops}

        return {"status": "error", "message": f"Unknown action: {action}"}