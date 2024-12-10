import tkinter as tk
from tkinter import ttk, scrolledtext
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time

# Importar funciones del backend
from backend import iniciar_backend, obtener_estadisticas, obtener_notificaciones, lista_negra_ips, obtener_usuarios_conectados

# Variables globales
paquetes_por_segundo = []
x_tiempo = []

# Función para actualizar datos en la interfaz
def actualizar_datos():
    global paquetes_por_segundo, x_tiempo

    try:
        # Obtener estadísticas del backend
        porcentajes_protocolos, tasa_solicitudes = obtener_estadisticas()
        # Obtener notificaciones del backend
        notifs = obtener_notificaciones()
        # Obtener usuarios conectados
        usuarios = obtener_usuarios_conectados()
    except Exception as e:
        print(f"Error al obtener estadísticas: {e}")
        return

    paquetes_por_segundo.append(tasa_solicitudes)
    if len(paquetes_por_segundo) > 20:
        paquetes_por_segundo.pop(0)

    # Actualizar etiquetas
    lbl_paquetes.config(text=f"Solicitudes por segundo: {tasa_solicitudes}")
    lbl_http.config(text=f"HTTP: {porcentajes_protocolos['HTTP']:.1f}%")
    lbl_https.config(text=f"HTTPS: {porcentajes_protocolos['HTTPS']:.1f}%")
    lbl_dns.config(text=f"DNS: {porcentajes_protocolos['DNS']:.1f}%")
    lbl_tcp.config(text=f"TCP: {porcentajes_protocolos['TCP']:.1f}%")
    lbl_udp.config(text=f"UDP: {porcentajes_protocolos['UDP']:.1f}%")
    lbl_ips_bloqueadas.config(text=f"IPs bloqueadas: {len(lista_negra_ips)}")

    # Actualizar lista de usuarios conectados
    usuarios_text.delete(1.0, tk.END)
    for ip in usuarios:
        usuarios_text.insert(tk.END, ip + "\n")

    # Actualizar gráficos
    actualizar_grafico_protocolos(porcentajes_protocolos)
    actualizar_grafico_solicitudes()

    # Registrar actividad en el log
    log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] Actualización completada\n")
    log_text.yview(tk.END)

    # Mostrar notificaciones en el widget de notificaciones
    for notif in notifs:
        notificaciones_text.insert(tk.END, notif + "\n")
        notificaciones_text.yview(tk.END)

    # Reprogramar actualización cada 5 segundos
    root.after(5000, actualizar_datos)

# Función para actualizar el gráfico de protocolos
def actualizar_grafico_protocolos(porcentajes):
    ax1.clear()
    protocolos = list(porcentajes.keys())
    valores = list(porcentajes.values())
    colores = ['blue', 'green', 'red', 'purple', 'orange']
    ax1.bar(protocolos, valores, color=colores)
    ax1.set_title("Distribución de Protocolos")
    ax1.set_ylabel("Porcentaje (%)")
    ax1.set_ylim(0, 100)
    for i, v in enumerate(valores):
        ax1.text(i, v + 1, f"{v:.1f}%", ha='center')
    canvas1.draw()

# Función para actualizar el gráfico de solicitudes por segundo
def actualizar_grafico_solicitudes():
    ax2.clear()
    tiempos = [i * 5 for i in range(len(paquetes_por_segundo))]
    ax2.plot(tiempos, paquetes_por_segundo, marker='o')
    ax2.set_title("Solicitudes por Segundo")
    ax2.set_xlabel("Tiempo (s)")
    ax2.set_ylabel("Solicitudes/s")
    ax2.grid(True)
    canvas2.draw()

# Función para iniciar la monitorización
def iniciar_monitorizacion():
    url = entrada_url.get()
    if not url:
        tk.messagebox.showwarning("Error", "Por favor, ingresa una URL o IP válida.")
        return
    log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] Iniciando monitorización para {url}\n")
    log_text.yview(tk.END)
    iniciar_backend(url)
    actualizar_datos()

# Configuración de la ventana principal
root = tk.Tk()
root.title("WAF - Firewall de Aplicaciones Web")
root.geometry("1200x900")

# Entrada de URL e inicio
frame_superior = tk.Frame(root)
frame_superior.pack(pady=10)

tk.Label(frame_superior, text="Ingresa la URL o IP a monitorizar:").pack(side=tk.LEFT, padx=5)
entrada_url = tk.Entry(frame_superior, width=50)
entrada_url.pack(side=tk.LEFT, padx=5)
boton_iniciar = tk.Button(frame_superior, text="Iniciar Monitorización", command=iniciar_monitorizacion)
boton_iniciar.pack(side=tk.LEFT, padx=5)

# Estadísticas
frame_estadisticas = tk.Frame(root)
frame_estadisticas.pack(pady=10)

lbl_paquetes = tk.Label(frame_estadisticas, text="Solicitudes por segundo: 0", font=("Arial", 12))
lbl_paquetes.pack()

lbl_http = tk.Label(frame_estadisticas, text="HTTP: 0%", font=("Arial", 12))
lbl_http.pack()

lbl_https = tk.Label(frame_estadisticas, text="HTTPS: 0%", font=("Arial", 12))
lbl_https.pack()

lbl_dns = tk.Label(frame_estadisticas, text="DNS: 0%", font=("Arial", 12))
lbl_dns.pack()

lbl_tcp = tk.Label(frame_estadisticas, text="TCP: 0%", font=("Arial", 12))
lbl_tcp.pack()

lbl_udp = tk.Label(frame_estadisticas, text="UDP: 0%", font=("Arial", 12))
lbl_udp.pack()

lbl_ips_bloqueadas = tk.Label(frame_estadisticas, text="IPs bloqueadas: 0", font=("Arial", 12))
lbl_ips_bloqueadas.pack()

# Gráficos
frame_graficos = tk.Frame(root)
frame_graficos.pack(pady=10, fill=tk.BOTH, expand=True)

# Gráfico de protocolos
fig1 = Figure(figsize=(5, 3))
ax1 = fig1.add_subplot(111)
canvas1 = FigureCanvasTkAgg(fig1, master=frame_graficos)
canvas1.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Gráfico de solicitudes por segundo
fig2 = Figure(figsize=(5, 3))
ax2 = fig2.add_subplot(111)
canvas2 = FigureCanvasTkAgg(fig2, master=frame_graficos)
canvas2.get_tk_widget().pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Notificaciones
frame_notificaciones = tk.LabelFrame(root, text="Notificaciones")
frame_notificaciones.pack(fill=tk.BOTH, expand=True, pady=10)

notificaciones_text = scrolledtext.ScrolledText(frame_notificaciones, wrap=tk.WORD, height=10)
notificaciones_text.pack(fill=tk.BOTH, expand=True)

# Usuarios conectados
frame_usuarios = tk.LabelFrame(root, text="Usuarios Conectados")
frame_usuarios.pack(fill=tk.BOTH, expand=True, pady=10)

usuarios_text = scrolledtext.ScrolledText(frame_usuarios, wrap=tk.WORD, height=5)
usuarios_text.pack(fill=tk.BOTH, expand=True)

# Log de eventos
frame_inferior = tk.LabelFrame(root, text="Log de Eventos")
frame_inferior.pack(fill=tk.BOTH, expand=True, pady=10)

log_text = scrolledtext.ScrolledText(frame_inferior, wrap=tk.WORD, height=10)
log_text.pack(fill=tk.BOTH, expand=True)

# Iniciar la aplicación
root.mainloop()
