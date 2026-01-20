import csv
import os
import datetime
import folium
import webbrowser
from tkinter import filedialog, messagebox

def export_results(data, export_type="csv"):
    """
    Exports the given list of dictionaries (data) to a file.
    Supports CSV and HTML formats.
    """
    if not data:
        messagebox.showwarning("Export", "No data to export.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if export_type == "csv":
        _export_to_csv(data, timestamp)
    elif export_type == "html":
        _export_to_html(data, timestamp)

def generate_visual_map(hops_data):
    try:
        m = folium.Map(location=[0, 0], zoom_start=2, tiles="CartoDB dark_matter")
        coordinates = []

        for hop in hops_data:
            # Extração segura das coordenadas
            lat = hop.get('lat')
            lon = hop.get('lon')
            
            if lat and lon:
                pos = [lat, lon] # Definido dentro do escopo
                coordinates.append(pos)
                
                folium.Marker(
                    location=pos,
                    popup=f"Hop {hop['ttl']}: {hop['ip']}<br>{hop.get('display', '')}",
                    icon=folium.Icon(color='red' if "Hong Kong" in str(hop.get('display', '')) else 'blue')
                ).add_to(m)

        if not coordinates:
            print("DEBUG [Map]: Nenhuma coordenada encontrada nos hops.")
            return None

        if len(coordinates) > 1:
            folium.PolyLine(coordinates, color="#32CD32", weight=3, opacity=0.8).add_to(m)

        map_path = os.path.abspath("traceroute_map.html")
        m.save(map_path)
        print(f"DEBUG [Map]: Mapa salvo em {map_path}")
        return map_path
    except Exception as e:
        print(f"ERRO NO REPORT_UTILS: {e}")
        return None

def _export_to_csv(data, timestamp):
    filename = filedialog.asksaveasfilename(
        initialfile=f"scan_results_{timestamp}.csv",
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
    )
    if not filename: return

    try:
        keys = data[0].keys()
        with open(filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(data)
        messagebox.showinfo("Export Success", f"Data exported to {filename}")
    except Exception as e:
        messagebox.showerror("Export Error", f"Failed to export CSV: {e}")

def _export_to_html(data, timestamp):
    filename = filedialog.asksaveasfilename(
        initialfile=f"scan_results_{timestamp}.html",
        defaultextension=".html",
        filetypes=[("HTML Files", "*.html"), ("All Files", "*.*")]
    )
    if not filename: return

    try:
        keys = data[0].keys()
        html_content = f"""
        <html>
        <head>
            <title>Network Scan Report - {timestamp}</title>
            <style>
                body {{ font-family: sans-serif; padding: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h2>Network Scan Results</h2>
            <p>Generated on: {datetime.datetime.now()}</p>
            <table>
                <tr>
                    {''.join(f'<th>{key.upper()}</th>' for key in keys)}
                </tr>
                {''.join('<tr>' + ''.join(f'<td>{row[k]}</td>' for k in keys) + '</tr>' for row in data)}
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        messagebox.showinfo("Export Success", f"Data exported to {filename}")
    except Exception as e:
        messagebox.showerror("Export Error", f"Failed to export HTML: {e}")