<p align="center">
  <img src="https://64.media.tumblr.com/1d37914b7c284b85c241ff1f1f35f3cf/tumblr_o1w930oG4R1sfxb96o1_500.gifv" alt="animated"/>
</p>


---

# ARPspoofer + Tkinter

## ¿Qué es ARPSpoofer?

Hoy te traigo una versión para usar en Windows de ARPSpoofer. ARPSpoofer es una técnica utilizada en redes internas para realizar ataques de tipo MITM (Man in the Middle), DoS o para interceptar tráfico de datos. Puede emplearse en combinación con técnicas como DNS spoofing y sniffing para obtener información del tráfico de la red. Address Resolution Protocol (ARP por sus siglas en inglés) es un protocolo de capa 2 en el modelo OSI de comunicaciones, encargado de resolver direcciones IP en direcciones MAC. (Fuente: WeLiveSecurity)

---
<p align="center">
  <img src="https://i.imgur.com/qORa8nR_d.webp?maxwidth=760&fidelity=grand" alt="animated"/>
</p>

## ¿Cómo funciona esta aplicación?

ARPSpoofer + Tkinter permite realizar ataques de suplantación ARP de manera sencilla mediante una interfaz gráfica. Con esta herramienta puedes escanear la red para identificar dispositivos conectados, ejecutar ataques de suplantación ARP dirigidos a una víctima específica o lanzar ataques globales sobre todos los dispositivos de la red detectados.

### Funcionalidades principales:

- **Escaneo de la red:** Puedes especificar una red en formato CIDR (por ejemplo, `192.168.1.0/24`) para descubrir dispositivos conectados y visualizar sus direcciones IP y MAC en una tabla.
- **Ataque dirigido:** Permite seleccionar una víctima específica e iniciar el ataque ARP Spoofing contra ella. Se debe indicar la IP del router y la IP de la víctima.
- **Ataque global:** Ataca automáticamente todos los dispositivos detectados en la red, excluyendo la IP del router y la IP del equipo que ejecuta el ataque.
- **Sniffer de paquetes:** Se puede activar un analizador de tráfico en una ventana separada, que permite capturar y visualizar paquetes de datos filtrados por protocolos específicos.
- **Redirección de tráfico:** La aplicación incluye una opción para que la víctima mantenga la conectividad a Internet durante el ataque, permitiendo el análisis del tráfico en tiempo real.
- **Protección contra detección:** Algunos antivirus pueden detectar este tipo de ataque, por lo que es importante revisar las configuraciones de seguridad antes de ejecutarlo.

Puedes descargar el ejecutable de la aplicación en el siguiente enlace:

[Descargar ARPSpoofer + Tkinter v2.0](https://github.com/Lithiuhm/ARPSpoofing-and-Tkinter/releases/tag/ARPSpoofing-and-Tkinterv2.0)

---

# Instalación

Una vez entendido todo esto procedemos a ver el programa en funcionamiento

Recomiendo encarecidamente que para este tipo de programas instalemos dependencias dentro de un entorno virtual de Python. Para ello, facilito la documentación oficial de Python para aprender a crearlo:

[Python](https://www.python.org/)

Lo primero es descargar el repositorio. Puedes hacerlo descargándolo como `.zip` en esta misma página o clonando el repositorio en tu PC con el siguiente comando:

```bash
git clone https://github.com/Lithiuhm/ARPSpoofing-and-Tkinter.git
```

Dicho esto, lo primero es instalar las dependencias necesarias para ejecutar el programa. Ejecuta el siguiente comando en una consola:

```bash
pip install scapy
```

Además, para poder enviar y recibir paquetes, debemos tener instalado **Npcap** en lugar de WinPcap. Puedes descargarlo desde la siguiente página oficial:

[Descargar Npcap](https://nmap.org/npcap/)

Ahora solo queda ejecutarlo:

```bash
python3 arpspoofer.py
```

---

# Uso

<p align="center">
  <img src="https://i.imgur.com/9fpss3M.gif" alt="animated"/>
</p>

### Paso 1: Descubrir la red

Antes de realizar cualquier ataque, es necesario identificar la red en la que estamos operando. Para ello, abre una consola y escribe:

```bash
ipconfig
```

Aquí obtendrás información importante como la dirección IP de tu equipo, la máscara de subred y la puerta de enlace predeterminada. Un ejemplo sería:

- **IP:** 10.0.2.15
- **Máscara:** 255.255.255.0
- **Puerta de enlace:** 10.0.2.2

### Paso 2: Escaneo de la red

Introduce la dirección de la red en la aplicación en formato CIDR, por ejemplo, `10.0.2.0/24`. Esto permitirá descubrir todos los dispositivos conectados a la red local.

### Paso 3: Realizar un ataque ARP Spoofing

- **Ataque dirigido:** Si deseas atacar una víctima específica, introduce su dirección IP en el campo "IP objetivo" y la dirección IP del router en "IP del router". Luego, presiona "Iniciar Ataque Individual".
- **Ataque global:** Si deseas atacar toda la red, introduce la IP del router y presiona "Iniciar Ataque Global". Esto afectará a todos los dispositivos detectados menos el router y el equipo atacante.

**¡Abierto a cualquier ayuda y comentario!**

---

# Próximas versiones

En futuras versiones, se implementarán nuevas funcionalidades para mejorar la experiencia y eficacia del ataque MITM:

- **Redirección de paquetes:** Se añadirá una función que permitirá mantener la conexión a Internet de la víctima mientras el tráfico pase a través del atacante, permitiendo la manipulación y análisis del tráfico en tiempo real.
- **Sniffer integrado:** Se incorporará un sistema de captura y análisis de paquetes dentro de la aplicación, eliminando la necesidad de herramientas externas como Wireshark y facilitando la interceptación de datos en ataques MITM.


---

# Descargo de responsabilidad

No me hago responsable del mal uso que se le dé a esta aplicación. Todo esto es con fines educativos e informativos. ¡Gracias y a disfrutarlo!

## Autor

- [@Lithiuhm](https://www.github.com/Lithiuhm)

