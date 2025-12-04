from scapy.all import get_if_list, get_if_addr, conf

print("=== SCAPY INTERFACE DIAGNOSIS ===")
print(f"Scapy Default Interface: {conf.iface}")

print("\nListing all detected interfaces:")
try:
    # Get list of interfaces (GUIDs on Windows)
    interfaces = get_if_list()
    
    for iface in interfaces:
        try:
            # Try to get the IP address associated with this interface
            ip = get_if_addr(iface)
            
            # Highlight the one Scapy was using in your logs
            marker = " <--- USED IN LOGS" if "{FC528DED-1309-4AA5-B5B0-C17E8C41405D}" in iface else ""
            
            # Highlight the one with your local IP
            ip_marker = " <--- YOUR LOCAL IP (CORRECT)" if ip.startswith("192.168.3") else ""
            
            print(f"GUID: {iface}")
            print(f"  IP: {ip} {marker}{ip_marker}")
            print("-" * 30)
            
        except Exception as e:
            print(f"GUID: {iface} (Error reading IP: {e})")

except Exception as e:
    print(f"Critical Error listing interfaces: {e}")

print("\n=== INSTRUCTIONS ===")
print("1. Look for the GUID that has your IP (192.168.3.x).")
print("2. If it DOES NOT match the GUID Scapy used in your logs, Scapy is picking the wrong card.")