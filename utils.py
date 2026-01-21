import os
import sys
import time
import threading
import logging 
import platform
import subprocess
import re  # Adicionado para validação de Regex
from datetime import datetime

def get_executable_dir():
    # Returns dir where executable is located
    if getattr(sys, 'frozen', False):
        # Running as compiled
        return os.path.dirname(sys.executable)
    else:
        # Running as .py script
        return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_executable_dir()
LOG_FILE = os.path.join(BASE_DIR, "LOGS", "gen_log.txt")

# --- FUNÇÕES MOVIDAS DO GUI_APP (Lógica de Sistema/Path/Validação) ---

def resource_path(relative_path):
    """ Retorna o caminho absoluto do recurso, funcionando para dev e para PyInstaller """
    try:
        # PyInstaller cria uma pasta temp e armazena o caminho em _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def check_npcap_silent():
    """ Verifica silenciosamente se o Npcap (driver de captura) existe no Windows """
    if platform.system() != "Windows":
        return True
    try:
        npcap_path = os.path.join(os.environ["WINDIR"], "System32", "Npcap", "wpcap.dll")
        return os.path.exists(npcap_path)
    except Exception:
        return False

def is_valid_target(target):
    """ Valida se o alvo é um IP, CIDR ou Domínio válido usando Regex """
    # Regex para IP Simples ou CIDR (ex: 192.168.0.1 ou 192.168.0.1/24)
    ip_cidr_pattern = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(/\d{1,2})?$"
    
    # Regex para Domínios (ex: google.com, sub.dominio.com.br)
    domain_pattern = r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"

    if re.match(ip_cidr_pattern, target) or re.match(domain_pattern, target, re.IGNORECASE):
        return True
    return False

# -------------------------------------------------------------------

def suppress_scapy_warnings():
    # Globally suppresses Scapy verbosity.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def _log_operation(message: str, level: str = "INFO", destination=LOG_FILE):
     # Logs operations to a file with a timestamp.
    try:
        folder = os.path.dirname(destination)
        if folder and not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)

        with open(destination, "a", encoding="utf-8") as f:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            if level == "REPORT":
                f.write(f"{message}\n")
            else:
                f.write(f"[{timestamp}] [{level.upper()}] - {message}\n")
                
    except Exception as e:
        print(f"Failure in writing log '{destination}'. Error: {e}")

def configure_firewall():
    # Tries adding windows firewall rules to allow inbound on ports 5050 and 5051 for TCP and UDP. Requires admin
    # Returns: (bool, str) -> (Success, Message)
    
    if platform.system() != "Windows":
        return False, "Firewall: N/A (Non-Windows)"

    try:
        # Regra TCP
        subprocess.run(
            'netsh advfirewall firewall add rule name="PyNetSketch TCP" dir=in action=allow protocol=TCP localport=5050',
            shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Regra UDP
        subprocess.run(
            'netsh advfirewall firewall add rule name="PyNetSketch Discovery" dir=in action=allow protocol=UDP localport=5051',
            shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
        return True, "✅ Firewall Configured (Ports 5050/5051 open)"
        
    except Exception as e:
        return False, f"⚠️ Error configuring Firewall: {e}"

def run_in_background(target_func, callback_func, progress_callback=None, *args, **kwargs):
    # Runs a specific function in a separate thread.
    
    stop_event = threading.Event()
    
    def wrapper():
        try:
            func_name = target_func.__name__
            _log_operation(f"Thread started for: {func_name}")
            
            # Inject control objects
            kwargs['stop_event'] = stop_event
            if progress_callback:
                kwargs['progress_callback'] = progress_callback
            
            # Run the heavy blocking function
            result = target_func(*args, **kwargs)
            
            # CRITICAL FIX: Always run the callback so the GUI can reset buttons,
            # even if the user clicked Stop.
            if callback_func:
                callback_func(result)
                
            if stop_event.is_set():
                _log_operation(f"Thread cancelled/stopped for: {func_name}", "WARN")
            else:
                _log_operation(f"Thread finished for: {func_name}")
            
        except Exception as e:
            _log_operation(f"Thread error in {target_func.__name__}: {e}", "ERROR")

    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()
    return stop_event