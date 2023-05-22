<p align="center">
  <img src="https://64.media.tumblr.com/1d37914b7c284b85c241ff1f1f35f3cf/tumblr_o1w930oG4R1sfxb96o1_500.gifv" alt="animated"/>
</p>

---

# ARPspoofer + Tkinter

¿Qué es ARPSpoofer?

Hoy te traigo una versión para usar en Windows de ARPSpoofer, ARPSpoofer en sencillas palabras es una técnica usada comúnmente por atacantes en redes internas para ataques MITM, DOS o para explotar algún fallo en la victima para obtener acceso al equipo en combinación con técnicas como DNSspoof y sniffing, entre otras. Address Resolution Protocol (ARP por su siglas en inglés) es un protocolo de capa 2 en el modelo OSI de comunicaciones, que básicamente se encarga de resolver direcciones IP y MAC. (según welivesecurity)

---
# Instalación

Una vez entendido todo esto procedemos a ver el programa en funcionamiento

Recomiendo encarecidamente que para este tipo de programas instalemos dependencia dentro de un entorno virtual de Python, para ello facilito la documentación oficial de Python para aprender a crearlo. 

```bash
https://docs.python.org/es/3.8/library/venv.html
```

Lo primero es descargar el repositorio, lo puedes hacer descargandolo como .zip en esta misma página aqrriba a la derecha o clonando el repositorio en tu pc

```bash
gh clone https://github.com/Lithiuhm/ARPSpoofing-and-Tkinter.git
```

Dicho esto, lo primero es instalar las dependencias necesarias para ejecutar el programa, ejecutamos el siguiente comando en una consola

```bash
pip install scapy
```

Admeás para poder enviar y recibir paquetes debemos tener instalado Wincap y lo descargamos de la siguiente página

```bash
https://www.winpcap.org/install/default.htm
```

Ahora solo queda ejecutarlo!

```bash
python3 arpspoofertk.py
```

---

# Uso

Ahora se te abrirá una pestaña así

<img src="/images/img1.png"/>

Primero descubriremos la red para saber en que red estamos, para saberlo abrimos una consola y escribimos

```bash
ipconfig
```

Aquí obtenemos toda la información importante la red, máscara y puerta de enlace, en mi caso son:

- IP:                 10.0.2.15
- Máscara:            255.255.255.0
- Puerta de enlace:   10.0.2.2

<img src="/images/img2.png"/>


Ahora ponemos la dirección de red más la máscara, en mi caso puse 10.0.2.0/24 ya que esa es mi dirección de red, en cada caso pude variar.

<img src="/images/img3.png"/>

Por último escribimos en la ip a atacar la dirección de la víctima y en la ip del router la ip de la puerta de enlace y finalmente estámos enviando paquetes tanto a la víctima haciendonos pasar por el rutes y al router haciendonos pasar por la víctima

<img src="/images/img4.png"/>


**¡Abierto a cualquier ayuda y commentario!**

---

# Descargo de responsabilidad

No me hago cargo del mal uso que se le de a esta aplicación, todo esto es con fines educativos e informativos, gracias y a disfrutarlo!
## Autor

- [@Lithiuhm](https://www.github.com/Lithiuhm)

