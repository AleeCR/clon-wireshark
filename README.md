# 🦈 Wireshark Clone con Flask

## 📌 Descripción

Este proyecto es un clon básico de **Wireshark**, hecho en **Python** usando **Flask** y **Scapy**. Permite capturar, visualizar y guardar paquetes de red a través de una interfaz web moderna que separa HTML, CSS y JavaScript. Es ideal para estudio, monitoreo local y aprendizaje sobre tráfico de red y desarrollo web.

## ⚙️ Tecnologías utilizadas

- **Python 3** – Lógica principal del backend
- **Flask** – Framework web para montar la API y servir la interfaz
- **Scapy** – Captura y análisis de paquetes de red
- **HTML5 + CSS + JavaScript** – Interfaz de usuario modular y responsiva

## 🌟 Características principales

- Selección de interfaz de red para capturas
- Filtros de captura (ej: solo TCP, solo UDP)
- Visualización en tiempo real de los paquetes capturados
- Detalle de cada paquete con información técnica
- Guardado de capturas en formato .pcap
- Interfaz web moderna.

## 🚀 Instalación y uso

git clone https://github.com/AleeCR/clon-wireshark.git
cd clon-wireshark
pip install -r requirements.txt
python wireshark.py



> ⚠️ **Requiere permisos de administrador/root para capturar paquetes de red**

Luego, abre tu navegador y accede a [http://localhost:5000](http://localhost:5000).

## 📂 Estructura del proyecto

wireshark-clone-flask/
│ wireshark.py
│ requirements.txt
│ README.md
├── templates/
│ └── index.html
├── static/
│ ├── styles.css
│ └── script.js

text
- **wireshark.py**: servidor Flask y lógica de captura
- **templates/**: HTML (interfaz principal)
- **static/**: estilos CSS y JavaScript de frontend

