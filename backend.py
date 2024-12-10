import socket
from scapy.all import sniff, TCP, UDP, DNS, Raw, IP
import time
import pandas as pd
import numpy as np
from threading import Lock
import os

# Variables globales protegidas con locks
conteo_paquetes = 0
tiempos_paquetes = []
protocolos_contador = {'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0}
lista_negra_ips = []
notificaciones = []  # Lista de notificaciones para el frontend
usuarios_conectados = set()
lock = Lock()

# DataFrame para registrar intentos de inicio de sesión
# Columnas: 'ip', 'timestamp', 'status' ('success' o 'failure')
login_attempts = pd.DataFrame(columns=['ip', 'timestamp', 'status'])

def procesar_paquete(paquete):
    global conteo_paquetes, tiempos_paquetes, protocolos_contador, notificaciones, usuarios_conectados, login_attempts
    with lock:
        conteo_paquetes += 1
        tiempos_paquetes.append(time.time())

        src_ip = paquete[IP].src if paquete.haslayer(IP) else 'Desconocida'

        # Clasificar protocolos
        if paquete.haslayer(TCP):
            if paquete.dport == 80 or paquete.sport == 80:
                protocolos_contador['HTTP'] += 1
                usuarios_conectados.add(src_ip)
            elif paquete.dport == 443 or paquete.sport == 443:
                protocolos_contador['HTTPS'] += 1
                usuarios_conectados.add(src_ip)
            else:
                protocolos_contador['TCP'] += 1
        elif paquete.haslayer(UDP):
            if paquete.haslayer(DNS):
                protocolos_contador['DNS'] += 1
            else:
                protocolos_contador['UDP'] += 1

        # Detectar patrones de ataque o tráfico sospechoso
        if paquete.haslayer(Raw):
            try:
                carga = paquete[Raw].load.decode(errors='ignore').lower()

                # Detección de inyección SQL
                patrones_sql = ['select', 'insert', 'update', 'delete', 'drop', 'union', '--', '#', '/*', '*/', "' or '1'='1"]
                if any(patron in carga for patron in patrones_sql):
                    ip_atacante = src_ip
                    mensaje = f"[{time.strftime('%H:%M:%S')}] Inyección SQL detectada desde {ip_atacante}"
                    notificaciones.append(mensaje)
                    bloquear_ip(ip_atacante)
                    cerrar_sesion(ip_atacante)

                # Detección de intentos de inicio de sesión
                if 'login' in carga:
                    if 'failed' in carga or 'incorrect' in carga:
                        registrar_intento_login(src_ip, 'failure')
                    elif 'success' in carga:
                        registrar_intento_login(src_ip, 'success')

            except Exception as e:
                pass

def registrar_intento_login(ip, status):
    global login_attempts, notificaciones
    timestamp = time.time()
    nuevo_intento = pd.DataFrame({'ip': [ip], 'timestamp': [timestamp], 'status': [status]})
    login_attempts = pd.concat([login_attempts, nuevo_intento], ignore_index=True)

    # Filtrar intentos fallidos en los últimos 5 minutos
    limite_tiempo = timestamp - 300  # 5 minutos
    intentos_recientes = login_attempts[(login_attempts['ip'] == ip) &
                                        (login_attempts['timestamp'] >= limite_tiempo) &
                                        (login_attempts['status'] == 'failure')]

    if len(intentos_recientes) >= 4:
        mensaje = f"[{time.strftime('%H:%M:%S')}] Múltiples intentos fallidos de inicio de sesión desde {ip}"
        notificaciones.append(mensaje)
        bloquear_ip(ip)
        cerrar_sesion(ip)

def bloquear_ip(ip):
    global lista_negra_ips, notificaciones
    if ip not in lista_negra_ips:
        lista_negra_ips.append(ip)
        mensaje = f"[{time.strftime('%H:%M:%S')}] IP bloqueada: {ip}"
        notificaciones.append(mensaje)
        print(mensaje)
        # Comando para bloquear la IP (ejemplo para sistemas Linux)
        # os.system(f"iptables -A INPUT -s {ip} -j DROP")

def cerrar_sesion(ip):
    global notificaciones
    # Lógica para cerrar sesión del usuario
    # Esto depende de cómo maneje las sesiones tu aplicación web
    # Aquí sólo agregamos una notificación
    mensaje = f"[{time.strftime('%H:%M:%S')}] Sesión cerrada para IP: {ip}"
    notificaciones.append(mensaje)
    print(mensaje)
    # Implementar aquí la lógica para cerrar la sesión en la aplicación web

def obtener_estadisticas():
    global protocolos_contador, tiempos_paquetes
    with lock:
        # Calcular porcentajes de protocolos
        total_paquetes = sum(protocolos_contador.values())
        porcentajes = {protocolo: (cantidad / total_paquetes) * 100 if total_paquetes > 0 else 0
                       for protocolo, cantidad in protocolos_contador.items()}

        # Calcular solicitudes por segundo
        tiempos_actualizados = [t for t in tiempos_paquetes if t > time.time() - 1]
        tasa_solicitudes = len(tiempos_actualizados)
        tiempos_paquetes[:] = tiempos_actualizados  # Actualizar la lista para evitar crecimiento infinito

    return porcentajes, tasa_solicitudes

def obtener_notificaciones():
    global notificaciones
    with lock:
        notifs = notificaciones.copy()
        notificaciones.clear()
    return notifs

def obtener_usuarios_conectados():
    global usuarios_conectados
    with lock:
        usuarios = list(usuarios_conectados)
    return usuarios

def monitorizar_trafico(url):
    print(f"Iniciando monitorización para: {url}")
    sniff(prn=procesar_paquete, store=False)

def iniciar_backend(url):
    from threading import Thread
    hilo_monitorizacion = Thread(target=monitorizar_trafico, args=(url,))
    hilo_monitorizacion.daemon = True
    hilo_monitorizacion.start()
