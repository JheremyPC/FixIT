"""Domain vocabulary for the synthetic FixIT dataset.

Everything here is fictitious. Values were chosen so that the generated tickets carry
plausible, learnable relationships (category complexity, priority, technician speed and
load all influence resolution time), which is what the ML pipeline needs to be evaluated.
"""

SYNTHETIC_TICKET_PREFIX = "SYN-"
SYNTHETIC_EMAIL_DOMAIN = "sintetico.fixit.example"
SYNTHETIC_SETTING_KEY = "synthetic.dataset"

AREAS = {
    # name: (relative ticket volume, priority bias added to ALTA/CRITICA weights)
    "Tecnología": (1.0, 0.05),
    "Administración": (1.1, 0.0),
    "Operaciones": (1.4, 0.08),
    "Recursos Humanos": (0.7, -0.03),
    "Finanzas": (1.0, 0.04),
    "Logística": (1.0, 0.06),
    "Comercial": (1.2, 0.02),
    "Dirección General": (0.4, 0.15),
}

SPECIALTIES = {
    "Redes y conectividad": "Red LAN/Wi-Fi, VPN y enlaces",
    "Hardware": "Equipos, periféricos y reparación",
    "Software y aplicaciones": "Instalación, errores y sistemas de gestión",
    "Accesos y cuentas": "Contraseñas, altas, bajas y permisos",
    "Impresión": "Impresoras, escáneres y multifuncionales",
    "Correo y colaboración": "Correo, calendario y videoconferencias",
    "Seguridad informática": "Phishing, malware y alertas de seguridad",
    "Telefonía": "Anexos, centralita y celulares corporativos",
    "Soporte general": "Atención general de primer nivel",
}

# name -> specialty, base work hours (median), volume weight, priority weights (BAJA, MEDIA, ALTA, CRITICA)
CATEGORIES = {
    "Conectividad de red": ("Redes y conectividad", 5.0, 1.2, (0.15, 0.40, 0.33, 0.12)),
    "VPN y acceso remoto": ("Redes y conectividad", 7.0, 0.8, (0.15, 0.45, 0.32, 0.08)),
    "Falla de hardware": ("Hardware", 26.0, 0.9, (0.15, 0.45, 0.30, 0.10)),
    "Periféricos": ("Hardware", 8.0, 1.0, (0.45, 0.42, 0.11, 0.02)),
    "Instalación de software": ("Software y aplicaciones", 10.0, 1.1, (0.40, 0.45, 0.13, 0.02)),
    "Errores de aplicación": ("Software y aplicaciones", 16.0, 1.0, (0.15, 0.45, 0.30, 0.10)),
    "Sistema ERP": ("Software y aplicaciones", 22.0, 0.7, (0.08, 0.40, 0.37, 0.15)),
    "Contraseñas y bloqueos": ("Accesos y cuentas", 1.5, 1.4, (0.20, 0.50, 0.25, 0.05)),
    "Altas y permisos": ("Accesos y cuentas", 9.0, 0.9, (0.30, 0.50, 0.17, 0.03)),
    "Impresoras y escáneres": ("Impresión", 7.0, 1.0, (0.35, 0.45, 0.17, 0.03)),
    "Correo electrónico": ("Correo y colaboración", 5.0, 1.0, (0.20, 0.48, 0.25, 0.07)),
    "Videoconferencia": ("Correo y colaboración", 4.0, 0.6, (0.25, 0.45, 0.25, 0.05)),
    "Incidente de seguridad": ("Seguridad informática", 12.0, 0.5, (0.03, 0.22, 0.40, 0.35)),
    "Telefonía y anexos": ("Telefonía", 10.0, 0.6, (0.30, 0.45, 0.20, 0.05)),
    "Incidencia general": ("Soporte general", 6.0, 0.5, (0.35, 0.45, 0.17, 0.03)),
}

# Category affinity per area (multiplies the volume weight).
AREA_CATEGORY_AFFINITY = {
    "Tecnología": {"Incidente de seguridad": 2.0, "Errores de aplicación": 1.4, "Instalación de software": 1.5},
    "Administración": {"Impresoras y escáneres": 1.6, "Correo electrónico": 1.3},
    "Operaciones": {"Falla de hardware": 1.6, "Periféricos": 1.5, "Conectividad de red": 1.3},
    "Recursos Humanos": {"Altas y permisos": 2.2, "Contraseñas y bloqueos": 1.3},
    "Finanzas": {"Sistema ERP": 2.4, "Impresoras y escáneres": 1.2},
    "Logística": {"Telefonía y anexos": 1.6, "Falla de hardware": 1.3, "Sistema ERP": 1.4},
    "Comercial": {"VPN y acceso remoto": 2.0, "Videoconferencia": 1.8, "Telefonía y anexos": 1.4},
    "Dirección General": {"Videoconferencia": 2.0, "Correo electrónico": 1.6},
}

PRIORITY_CODES = ("BAJA", "MEDIA", "ALTA", "CRITICA")
PRIORITY_SLA = {"BAJA": 72, "MEDIA": 48, "ALTA": 24, "CRITICA": 4}
# Attention delay median (hours) and work-time multiplier per priority.
PRIORITY_ATTENTION = {"BAJA": 10.0, "MEDIA": 3.5, "ALTA": 1.2, "CRITICA": 0.3}
PRIORITY_WORK = {"BAJA": 1.15, "MEDIA": 1.0, "ALTA": 0.75, "CRITICA": 0.45}

# Technicians: (full name, specialties, speed factor <1 is faster, quality 1-5, max load, available)
TECHNICIANS = [
    ("Lucía Fernández", ["Redes y conectividad", "Seguridad informática"], 0.75, 4.7, 10, True),
    ("Martín Quispe", ["Redes y conectividad", "Telefonía"], 0.95, 4.2, 9, True),
    ("Carla Rojas", ["Hardware", "Impresión"], 0.85, 4.5, 10, True),
    ("Diego Salazar", ["Hardware", "Soporte general"], 1.25, 3.7, 8, True),
    ("Valeria Huamán", ["Software y aplicaciones", "Correo y colaboración"], 0.80, 4.6, 10, True),
    ("Jorge Paredes", ["Software y aplicaciones"], 1.10, 4.0, 9, True),
    ("Andrea Torres", ["Accesos y cuentas", "Correo y colaboración"], 0.70, 4.4, 12, True),
    ("Ricardo Mendoza", ["Accesos y cuentas", "Soporte general"], 1.05, 3.9, 10, True),
    ("Sofía Chávez", ["Impresión", "Telefonía", "Soporte general"], 1.00, 4.1, 9, True),
    ("Kevin Ramos", ["Seguridad informática", "Software y aplicaciones"], 0.90, 4.3, 8, True),
    ("Paola Gutiérrez", ["Correo y colaboración", "Accesos y cuentas"], 1.20, 3.6, 9, True),
    ("Héctor Vargas", ["Hardware", "Redes y conectividad"], 1.35, 3.5, 8, True),
    ("Natalia Castro", ["Software y aplicaciones", "Soporte general"], 0.95, 4.2, 9, True),
    ("Óscar Delgado", ["Telefonía", "Impresión"], 1.15, 3.8, 8, False),
]

FIRST_NAMES = ["Ana", "Luis", "María", "Carlos", "Rosa", "José", "Elena", "Pedro", "Lucía", "Miguel", "Carmen",
               "Javier", "Patricia", "Fernando", "Gabriela", "Raúl", "Silvia", "Alberto", "Mónica", "Daniel",
               "Teresa", "Sergio", "Isabel", "Manuel", "Claudia", "Eduardo", "Verónica", "Rubén", "Diana", "Hugo"]
LAST_NAMES = ["García", "López", "Pérez", "Sánchez", "Ramírez", "Flores", "Díaz", "Morales", "Ortiz", "Castillo",
              "Reyes", "Cruz", "Romero", "Herrera", "Medina", "Aguilar", "Vega", "Campos", "Silva", "Núñez",
              "Ríos", "Cabrera", "Espinoza", "Ponce", "Valdivia", "Zapata", "Montes", "Salinas", "Navarro", "Luna"]

LOCATIONS = ["la oficina 2B", "el piso 3", "la sala de reuniones", "el almacén central", "recepción",
             "la sede norte", "contabilidad", "el área de despacho", "la oficina 105", "trabajo remoto"]

URGENT_PHRASES = ["Es urgente porque detiene la operación del área.", "Varias personas están afectadas.",
                  "Tenemos un cierre hoy y no podemos avanzar.", "Afecta la atención a clientes."]
CALM_PHRASES = ["No es urgente, pero agradecería revisarlo.", "Puedo seguir trabajando mientras tanto.",
                "Cuando tengan disponibilidad.", "Solo afecta a mi equipo."]

TITLES = {
    "Conectividad de red": ["Sin conexión a internet", "La red está muy lenta", "Wi-Fi se desconecta constantemente",
                            "Punto de red sin servicio"],
    "VPN y acceso remoto": ["No conecta la VPN", "VPN se cae cada pocos minutos", "No puedo acceder al escritorio remoto"],
    "Falla de hardware": ["La computadora no enciende", "Laptop se apaga sola", "Disco duro hace ruido",
                          "Pantalla azul al iniciar"],
    "Periféricos": ["El mouse no responde", "Teclado con teclas que no funcionan", "Monitor sin señal",
                    "Solicito cambio de audífonos"],
    "Instalación de software": ["Instalar programa de diseño", "Necesito Office en equipo nuevo",
                                "Instalación de lector PDF", "Actualizar navegador"],
    "Errores de aplicación": ["La aplicación se cierra sola", "Error al guardar archivos", "El sistema muestra un error 500",
                              "Programa muy lento al abrir"],
    "Sistema ERP": ["Error al registrar facturas en el ERP", "ERP no carga el módulo de inventario",
                    "No se generan reportes en el ERP", "Usuario sin acceso al ERP"],
    "Contraseñas y bloqueos": ["Olvidé mi contraseña", "Cuenta bloqueada", "Contraseña vencida", "No puedo iniciar sesión"],
    "Altas y permisos": ["Crear usuario para nuevo colaborador", "Acceso a carpeta compartida", "Permisos de administrador",
                         "Dar de baja usuario"],
    "Impresoras y escáneres": ["La impresora no imprime", "Atasco de papel frecuente", "El escáner no envía al correo",
                               "Impresora sin conexión"],
    "Correo electrónico": ["No me llegan correos", "Buzón lleno", "Outlook no sincroniza", "No puedo enviar adjuntos"],
    "Videoconferencia": ["No funciona la cámara en reuniones", "Sin audio en videollamadas", "Problemas con la sala de video"],
    "Incidente de seguridad": ["Recibí un correo sospechoso", "Alerta del antivirus", "Posible virus en el equipo",
                               "Hice clic en un enlace extraño"],
    "Telefonía y anexos": ["Anexo sin tono", "Celular corporativo no recibe llamadas", "No puedo transferir llamadas"],
    "Incidencia general": ["Consulta sobre el uso del equipo", "Solicitud de soporte", "Revisión general del equipo"],
}

SYMPTOMS = {
    "Conectividad de red": ["El indicador de red aparece con un signo de advertencia.", "Las páginas tardan mucho en cargar.",
                            "Los demás equipos del área sí tienen conexión."],
    "VPN y acceso remoto": ["El cliente VPN muestra error de autenticación.", "La conexión se corta al abrir el sistema interno."],
    "Falla de hardware": ["Al presionar el botón no hay luces ni sonido.", "El equipo se reinicia después de unos minutos.",
                          "Se escucha un ruido metálico en el CPU."],
    "Periféricos": ["Ya probé desconectarlo y conectarlo de nuevo.", "Funciona de forma intermitente."],
    "Instalación de software": ["Lo necesito para mis tareas diarias.", "El instalador pide permisos de administrador."],
    "Errores de aplicación": ["El error aparece al abrir un archivo grande.", "Ocurre desde la última actualización.",
                              "Muestra un mensaje de error sin más detalle."],
    "Sistema ERP": ["El módulo queda cargando y no avanza.", "Aparece un mensaje de error de base de datos.",
                    "Otros compañeros tienen el mismo problema."],
    "Contraseñas y bloqueos": ["Intenté varias veces y se bloqueó.", "El sistema dice que la contraseña expiró."],
    "Altas y permisos": ["Se necesita para que pueda empezar a trabajar.", "Tengo autorización de mi jefatura."],
    "Impresoras y escáneres": ["Los documentos quedan en cola sin imprimir.", "La pantalla de la impresora muestra un error."],
    "Correo electrónico": ["El último correo recibido es de ayer.", "Aparece un aviso de almacenamiento lleno."],
    "Videoconferencia": ["Los demás participantes no me escuchan.", "La cámara aparece en negro."],
    "Incidente de seguridad": ["El correo pedía actualizar mis datos bancarios.", "El antivirus detectó una amenaza y la puso en cuarentena.",
                               "El equipo abre ventanas que no reconozco."],
    "Telefonía y anexos": ["Al levantar el auricular no hay tono.", "Las llamadas entrantes se cortan."],
    "Incidencia general": ["Necesito orientación del equipo de soporte.", "No sé a qué categoría corresponde."],
}

DIAGNOSES = {
    "Conectividad de red": [("Cable de red dañado en el punto de conexión.", "Se reemplazó el cable y se verificó la navegación."),
                            ("Dirección IP duplicada en la red.", "Se liberó y renovó la IP; se reservó una IP fija."),
                            ("Punto de acceso Wi-Fi saturado.", "Se reinició el AP y se balanceó la carga de clientes.")],
    "VPN y acceso remoto": [("Certificado del cliente VPN vencido.", "Se renovó el certificado y se probó la conexión."),
                            ("Versión antigua del cliente VPN.", "Se actualizó el cliente VPN a la versión vigente.")],
    "Falla de hardware": [("Fuente de poder averiada.", "Se reemplazó la fuente de poder y se hicieron pruebas de carga."),
                          ("Disco duro con sectores defectuosos.", "Se cambió el disco por SSD y se restauró la información."),
                          ("Memoria RAM defectuosa.", "Se reemplazó el módulo de memoria y se ejecutó diagnóstico completo.")],
    "Periféricos": [("Periférico con desgaste físico.", "Se entregó un periférico nuevo."),
                    ("Controlador desactualizado.", "Se reinstaló el controlador y se verificó el funcionamiento.")],
    "Instalación de software": [("Software no instalado en el equipo.", "Se instaló el software con licencia corporativa."),
                                ("Falta de permisos para instalar.", "Se instaló mediante cuenta administradora y se validó.")],
    "Errores de aplicación": [("Archivo de configuración corrupto.", "Se restauró la configuración por defecto de la aplicación."),
                              ("Incompatibilidad con actualización reciente.", "Se aplicó el parche del proveedor."),
                              ("Caché local dañada.", "Se limpió la caché y se reinstaló la aplicación.")],
    "Sistema ERP": [("Rol del usuario sin permisos sobre el módulo.", "Se asignó el rol correcto en el ERP."),
                    ("Bloqueo de registros en la base de datos.", "Se liberaron los bloqueos con el proveedor del ERP."),
                    ("Error de integración con el servicio de facturación.", "Se reprocesaron los documentos tras corregir la integración.")],
    "Contraseñas y bloqueos": [("Cuenta bloqueada por intentos fallidos.", "Se desbloqueó la cuenta y se restableció la contraseña."),
                               ("Contraseña expirada.", "Se guió al usuario para cambiar su contraseña.")],
    "Altas y permisos": [("Solicitud de acceso nueva.", "Se creó la cuenta y se asignaron los permisos aprobados."),
                         ("Permisos insuficientes en carpeta compartida.", "Se agregó al usuario al grupo correspondiente.")],
    "Impresoras y escáneres": [("Cola de impresión bloqueada.", "Se reinició el servicio de cola y se limpiaron trabajos."),
                               ("Rodillo de arrastre desgastado.", "Se reemplazó el rodillo y se calibró la impresora."),
                               ("Configuración SMTP del escáner incorrecta.", "Se corrigió la configuración de envío a correo.")],
    "Correo electrónico": [("Buzón al límite de capacidad.", "Se archivó correo antiguo y se amplió la cuota."),
                           ("Perfil de Outlook dañado.", "Se recreó el perfil de correo y se sincronizó.")],
    "Videoconferencia": [("Permisos de cámara/micrófono deshabilitados.", "Se habilitaron los permisos y se probó en una reunión."),
                         ("Controlador de audio con fallas.", "Se actualizó el controlador de audio.")],
    "Incidente de seguridad": [("Correo de phishing dirigido.", "Se bloqueó el remitente, se cambió la contraseña y se alertó al personal."),
                               ("Malware detectado en el equipo.", "Se aisló el equipo, se ejecutó limpieza completa y se verificó."),
                               ("Falso positivo del antivirus.", "Se validó el archivo y se registró la excepción.")],
    "Telefonía y anexos": [("Anexo desconfigurado en la central.", "Se reconfiguró el anexo en la central telefónica."),
                           ("Chip del celular dañado.", "Se gestionó el cambio de chip con el operador.")],
    "Incidencia general": [("Consulta de uso.", "Se brindó orientación al usuario y se compartió la guía."),
                           ("Configuración básica pendiente.", "Se realizó la configuración solicitada.")],
}

REQUESTER_COMMENTS = ["¿Hay alguna novedad sobre mi solicitud?", "Gracias por la ayuda.", "El problema volvió a ocurrir esta mañana.",
                      "Adjunto más detalles: ocurre al iniciar el día.", "Estaré disponible en mi escritorio toda la tarde."]
TECH_COMMENTS = ["Se revisó el equipo de forma remota.", "Se coordinó visita al puesto del usuario.",
                 "Pendiente de repuesto, se solicitó a almacén.", "Se escaló consulta al proveedor.",
                 "Se realizaron pruebas iniciales, continúo con el diagnóstico."]
INTERNAL_COMMENTS = ["Nota interna: revisar historial del equipo.", "Nota interna: posible caso recurrente en el área.",
                     "Nota interna: validar garantía con el proveedor."]
RATING_COMMENTS = {5: "Excelente atención, muy rápida.", 4: "Buena atención.", 3: "Se resolvió, pero tardó un poco.",
                   2: "Demoró bastante en resolverse.", 1: "No quedé conforme con la atención."}
