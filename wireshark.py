from flask import Flask, request, jsonify, send_file
import scapy.all as scapy
import threading
import time
from datetime import datetime
import os
import io
import tempfile
import socket
import psutil

app = Flask(__name__)

# Variables globales
capturing = False
packets = []
capture_thread = None
capture_lock = threading.Lock()

# Servir el archivo HTML estático
@app.route('/')
def index():

    with open('templates/index.html', 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capturing, capture_thread
    with capture_lock:
        if capturing:
            return jsonify({'status': 'error', 'message': 'Captura ya en curso'})
        
        data = request.get_json()
        interface = data.get('interface') if data else None
        filter_str = data.get('filter', '') if data else ''
        
        if not interface:
            return jsonify({'status': 'error', 'message': 'Interfaz requerida'})
        
        # Limpiar paquetes anteriores
        packets.clear()
        capturing = True
        
        # Iniciar captura en hilo separado
        capture_thread = threading.Thread(target=capture_packets, args=(interface, filter_str))
        capture_thread.daemon = True
        capture_thread.start()
        
        return jsonify({'status': 'success', 'message': 'Captura iniciada'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capturing, capture_thread
    with capture_lock:
        capturing = False
        
    # Esperar a que el hilo termine
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2)  # Esperar máximo 2 segundos
        
    return jsonify({'status': 'success', 'message': 'Captura detenida'})

@app.route('/get_packets', methods=['GET'])
def get_packets():
    with capture_lock:
        packet_data = []
        for i, p in enumerate(packets):
            try:
                # Extraer información de IP si está disponible
                src = ''
                dst = ''
                protocol = p.__class__.__name__
                
                if scapy.IP in p:
                    src = p[scapy.IP].src
                    dst = p[scapy.IP].dst
                elif scapy.IPv6 in p:
                    src = p[scapy.IPv6].src
                    dst = p[scapy.IPv6].dst
                elif scapy.ARP in p:
                    src = p[scapy.ARP].psrc
                    dst = p[scapy.ARP].pdst
                    protocol = 'ARP'
                elif scapy.Ether in p:
                    src = p[scapy.Ether].src
                    dst = p[scapy.Ether].dst
                    
                # Determinar protocolo más específico
                if scapy.TCP in p:
                    protocol = 'TCP'
                elif scapy.UDP in p:
                    protocol = 'UDP'
                elif scapy.ICMP in p:
                    protocol = 'ICMP'
                
                packet_info = {
                    'no': i + 1,
                    'time': datetime.fromtimestamp(float(p.time)).strftime('%H:%M:%S.%f')[:-3],
                    'src': src,
                    'dst': dst,
                    'protocol': protocol,
                    'length': len(p),
                    'info': p.summary()
                }
                packet_data.append(packet_info)
                
            except Exception as e:
                # Si hay error procesando un paquete, agregar info básica
                packet_data.append({
                    'no': i + 1,
                    'time': 'Error',
                    'src': 'Error',
                    'dst': 'Error', 
                    'protocol': 'Error',
                    'length': 0,
                    'info': f'Error procesando paquete: {str(e)}'
                })
        
        return jsonify({'packets': packet_data})

@app.route('/get_packet_details/<int:index>', methods=['GET'])
def get_packet_details(index):
    with capture_lock:
        if 0 <= index < len(packets):
            try:
                details = packets[index].show(dump=True)
                return jsonify({'details': details})
            except Exception as e:
                return jsonify({'details': f'Error mostrando detalles: {str(e)}'})
        return jsonify({'details': 'Paquete no encontrado'})

@app.route('/save_capture', methods=['GET'])  # Cambiado a GET para funcionar con window.location.href
def save_capture():
    with capture_lock:
        if not packets:
            return jsonify({'status': 'error', 'message': 'No hay paquetes para guardar'})
        
        try:
            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as temp_file:
                temp_filename = temp_file.name
                
            # Escribir paquetes al archivo usando scapy
            scapy.wrpcap(temp_filename, packets)
            
            # Enviar archivo y limpiarlo después
            def remove_file(response):
                try:
                    os.unlink(temp_filename)
                except:
                    pass
                return response
            
            return send_file(
                temp_filename,
                download_name=f'capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap',
                as_attachment=True,
                mimetype='application/vnd.tcpdump.pcap'
            )
            
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Error guardando captura: {str(e)}'})

def capture_packets(interface, filter_str):
    global capturing
    try:
        print(f"Iniciando captura en interfaz: {interface}")
        if filter_str:
            print(f"Filtro aplicado: {filter_str}")
        
        def packet_handler(packet):
            if capturing:
                with capture_lock:
                    packets.append(packet)
                    # Limitar número de paquetes en memoria para evitar overflow
                    if len(packets) > 10000:
                        packets.pop(0)
                print(f"Paquete capturado: {len(packets)}")
        
        # Captura continua sin timeout
        while capturing:
            try:
                # Usar sniff con timeout pequeño para permitir verificar capturing
                scapy.sniff(
                    iface=interface,
                    filter=filter_str if filter_str else None,
                    prn=packet_handler,
                    store=False,
                    timeout=0.5,  # Timeout pequeño para verificar estado
                    count=10      # Capturar máximo 10 paquetes por iteración
                )
            except Exception as e:
                if capturing:  # Solo mostrar error si aún estamos capturando
                    print(f"Error temporal en captura: {e}")
                time.sleep(0.1)  # Pequeña pausa antes de reintentar
        
        print("Captura detenida")
        
    except PermissionError:
        print("Error: Se requieren permisos de administrador para capturar paquetes")
        capturing = False
    except Exception as e:
        print(f"Error en captura: {e}")
        capturing = False

# Endpoint para obtener interfaces de red disponibles
@app.route('/get_interfaces', methods=['GET'])
def get_interfaces():
    try:
        import socket
        import psutil
        
        interfaces = []
        
        # Obtener todas las interfaces de Scapy
        scapy_interfaces = scapy.get_if_list()
        
        # Obtener información adicional de psutil
        net_if_stats = psutil.net_if_stats()
        net_if_addrs = psutil.net_if_addrs()
        
        for iface in scapy_interfaces:
            try:
                interface_info = {
                    'name': iface,
                    'display_name': iface,
                    'description': '',
                    'ip': '',
                    'status': 'unknown',
                    'type': 'ethernet'
                }
                
                # Intentar obtener IP de la interfaz
                try:
                    ip_addr = scapy.get_if_addr(iface)
                    if ip_addr and ip_addr != '0.0.0.0':
                        interface_info['ip'] = ip_addr
                except:
                    pass
                
                # Obtener información adicional de psutil
                if iface in net_if_stats:
                    stats = net_if_stats[iface]
                    interface_info['status'] = 'up' if stats.isup else 'down'
                    
                    # Determinar tipo de interfaz basado en el nombre
                    iface_lower = iface.lower()
                    if 'wi-fi' in iface_lower or 'wireless' in iface_lower or 'wlan' in iface_lower:
                        interface_info['type'] = 'wifi'
                    elif 'ethernet' in iface_lower or 'eth' in iface_lower or 'lan' in iface_lower:
                        interface_info['type'] = 'ethernet'
                    elif 'loopback' in iface_lower or 'lo' in iface_lower:
                        interface_info['type'] = 'loopback'
                    elif 'bluetooth' in iface_lower or 'bt' in iface_lower:
                        interface_info['type'] = 'bluetooth'
                
                # Obtener direcciones IP adicionales de psutil
                if iface in net_if_addrs and not interface_info['ip']:
                    for addr in net_if_addrs[iface]:
                        if addr.family == socket.AF_INET:  # IPv4
                            interface_info['ip'] = addr.address
                            break
                
                # Crear nombre más descriptivo
                if interface_info['type'] == 'wifi':
                    interface_info['display_name'] = f"📶 Wi-Fi - {interface_info['ip'] or 'Sin IP'}"
                elif interface_info['type'] == 'ethernet':
                    interface_info['display_name'] = f"🌐 Ethernet - {interface_info['ip'] or 'Sin IP'}"
                elif interface_info['type'] == 'loopback':
                    interface_info['display_name'] = f"🔄 Loopback - {interface_info['ip'] or '127.0.0.1'}"
                elif interface_info['type'] == 'bluetooth':
                    interface_info['display_name'] = f"📘 Bluetooth - {interface_info['ip'] or 'Sin IP'}"
                else:
                    # Intentar extraer nombre más limpio del nombre técnico
                    clean_name = iface
                    if '{' in clean_name:
                        # Extraer parte antes del GUID en Windows
                        clean_name = clean_name.split('{')[0].strip('_')
                    
                    interface_info['display_name'] = f"🔌 {clean_name} - {interface_info['ip'] or 'Sin IP'}"
                
                # Agregar estado si no está activa
                if interface_info['status'] == 'down':
                    interface_info['display_name'] += " (Inactiva)"
                
                # Solo agregar interfaces que parecen válidas
                if interface_info['status'] == 'up' or interface_info['ip']:
                    interfaces.append(interface_info)
                    
            except Exception as e:
                # Si hay error procesando una interfaz, agregar versión básica
                interfaces.append({
                    'name': iface,
                    'display_name': f"❓ {iface}",
                    'ip': '',
                    'status': 'unknown',
                    'type': 'unknown'
                })
        
        # Ordenar interfaces: primero las activas con IP, luego por tipo
        def sort_key(interface):
            priority = 0
            if interface['status'] == 'up' and interface['ip']:
                priority = 1
            if interface['type'] == 'ethernet':
                priority += 10
            elif interface['type'] == 'wifi':
                priority += 8
            elif interface['type'] == 'loopback':
                priority += 5
            return -priority  # Negativo para orden descendente
        
        interfaces.sort(key=sort_key)
        
        return jsonify({'interfaces': interfaces})
        
    except Exception as e:
        print(f"Error obteniendo interfaces: {e}")
        # Fallback a método básico
        try:
            basic_interfaces = scapy.get_if_list()
            interfaces = [{'name': iface, 'display_name': f"🔌 {iface}", 'ip': '', 'status': 'unknown', 'type': 'unknown'} for iface in basic_interfaces]
            return jsonify({'interfaces': interfaces})
        except:
            return jsonify({'interfaces': [], 'error': str(e)})

# Método alternativo de captura más robusto
def capture_packets_alternative(interface, filter_str):
    global capturing
    try:
        print(f"Iniciando captura alternativa en interfaz: {interface}")
        
        # Crear socket para captura continua
        def continuous_capture():
            packet_count = 0
            while capturing:
                try:
                    # Capturar paquetes de forma continua
                    pkts = scapy.sniff(
                        iface=interface,
                        filter=filter_str if filter_str else None,
                        timeout=1,
                        count=0  # Sin límite de paquetes
                    )
                    
                    if pkts and capturing:
                        with capture_lock:
                            for pkt in pkts:
                                packets.append(pkt)
                                packet_count += 1
                                # Limitar paquetes en memoria
                                if len(packets) > 10000:
                                    packets.pop(0)
                        print(f"Paquetes totales: {packet_count}")
                        
                except Exception as e:
                    if capturing:
                        print(f"Error en captura continua: {e}")
                        time.sleep(0.5)
                        
        continuous_capture()
        
    except Exception as e:
        print(f"Error en captura alternativa: {e}")
        capturing = False

if __name__ == '__main__':
    print("Iniciando servidor Wireshark Clone...")
    print("Nota: Se requieren permisos de administrador para la captura de paquetes")
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)