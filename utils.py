import os
import time
import threading
import logging 
import platform
import subprocess

# Use os.path.join for cross-platform compatibility
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "LOGS", "gen_log.txt")

def suppress_scapy_warnings():
    """
    Globally suppresses Scapy runtime warnings (like 'MAC address not found').
    Call this once at application startup.
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def _log_operation(message: str, level: str = "INFO", destination=LOG_FILE):
    """
    Logs operations to a file with a timestamp.
    Creates the directory if it doesn't exist.
    """
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
    """
    Tenta adicionar regras ao Windows Firewall para permitir conexões de entrada
    nas portas 5050 (TCP) e 5051 (UDP). Requer privilégios de Admin.
    Returns: (bool, str) -> (Success, Message)
    """
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
        
        return True, "✅ Firewall Configurado (Portas 5050/5051 Abertas)"
        
    except Exception as e:
        return False, f"⚠️ Erro ao configurar Firewall: {e}"

def run_in_background(target_func, callback_func, progress_callback=None, *args, **kwargs):
    """
    Runs a specific function in a separate thread.
    """
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