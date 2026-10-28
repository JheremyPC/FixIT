"""Terms of use and privacy notice shown by the web client (/legal and the in-app "Términos y privacidad" page).

DRAFT prepared by the technical team. Every "[PENDIENTE DE VALIDACIÓN INSTITUCIONAL]" marks content that only the
responsible institution can confirm (identity, legal basis, retention periods, official contacts). Publishing these
pages does not by itself make the platform compliant with Ley N.º 29733 or its regulation; the institution and a legal
specialist must review and approve them. To publish a reviewed text, edit it here and raise its ``version``: users are
then asked to accept the new terms version again (earlier acceptances stay on record).
"""
PENDING = "[PENDIENTE DE VALIDACIÓN INSTITUCIONAL]"
UPDATED = "2026-10-28"

TERMS = {
    "id": "terminos",
    "title": "Términos y condiciones de uso",
    "version": "0.1-borrador",
    "updated": UPDATED,
    "effective": PENDING,
    "requires_acceptance": True,
    "summary": "Reglas para usar FixIT: quién puede usarlo, qué está permitido y qué responsabilidades tiene cada parte.",
    "sections": [
        {"id": "objeto", "title": "1. Qué es FixIT y a quién se aplica", "blocks": [
            f"FixIT es la mesa de ayuda de tecnologías de la información de {PENDING} (en adelante, «la entidad»). Sirve para "
            "reportar incidencias técnicas, darles seguimiento y resolverlas.",
            "Estos términos se aplican a todas las personas que usan FixIT con una cuenta: solicitantes, técnicos, jefes de TI y "
            "administradores. Al crear tu cuenta o al aceptarlos desde la plataforma, declaras que los leíste y que los cumplirás.",
        ]},
        {"id": "cuentas", "title": "2. Cuentas y contraseñas", "blocks": [
            {"list": [
                "Tu cuenta es personal. No compartas tu contraseña ni permitas que otra persona trabaje con tu sesión.",
                "Usa una contraseña de al menos 8 caracteres que no utilices en otros servicios.",
                "Si sospechas que alguien usó tu cuenta, avisa de inmediato al área de TI para que la proteja y restablezca "
                f"tu contraseña ({PENDING}: canal oficial de reporte).",
                "Después de varios intentos fallidos de inicio de sesión, la cuenta se bloquea temporalmente para protegerla.",
                "Las cuentas pueden desactivarse cuando la persona deja de necesitar el servicio o incumple estos términos.",
            ]},
        ]},
        {"id": "roles", "title": "3. Roles y permisos", "blocks": [
            "Cada cuenta tiene un rol que define lo que puede ver y hacer:",
            {"list": [
                "Solicitante: crea tickets y consulta únicamente los suyos.",
                "Técnico: atiende los tickets que tiene asignados.",
                "Jefe de TI: supervisa la operación, asigna tickets, consulta reportes, indicadores de IA y la auditoría.",
                "Administrador: además gestiona usuarios, catálogos y la configuración.",
            ]},
            "Los permisos se verifican en el servidor. Intentar acceder a información que tu rol no permite está prohibido y "
            "queda registrado.",
        ]},
        {"id": "uso", "title": "4. Uso permitido y uso prohibido", "blocks": [
            "FixIT debe usarse solo para gestionar solicitudes de soporte técnico relacionadas con tus funciones. Está prohibido:",
            {"list": [
                "Registrar información falsa o ajena al soporte técnico.",
                "Incluir en tickets, comentarios o adjuntos datos personales que no sean necesarios, en especial datos sensibles "
                "(salud, datos biométricos, opiniones políticas, etc.), contraseñas o números de tarjetas.",
                "Subir archivos con software malicioso o contenido ilícito.",
                "Intentar acceder a cuentas, tickets o registros de otras personas, o eludir los controles de seguridad.",
                "Hacer pruebas de seguridad, cargas masivas o automatizaciones sin autorización escrita de la entidad.",
                "Usar el asistente de IA para fines ajenos al soporte técnico.",
            ]},
        ]},
        {"id": "contenido", "title": "5. Tickets, comentarios y adjuntos", "blocks": [
            "Eres responsable de lo que escribes y adjuntas. Solo se aceptan imágenes PNG o JPEG, documentos PDF y texto plano, "
            "de hasta 5 MB. Los comentarios internos solo son visibles para el personal de TI.",
            "El contenido de los tickets puede ser leído por el personal de TI que interviene en su atención y por los "
            "supervisores, y se usa para elaborar reportes e indicadores del servicio.",
        ]},
        {"id": "ia", "title": "6. Funciones de inteligencia artificial", "blocks": [
            "FixIT ofrece estimaciones (tiempo de resolución, riesgo de incumplir el plazo), sugerencias de prioridad, categoría, "
            "técnico o diagnóstico, y un asistente conversacional. Son ayudas: pueden equivocarse y no sustituyen el criterio de "
            "las personas. Las decisiones sobre los tickets las toma o confirma el personal responsable.",
            "Cuando el asistente está habilitado, el texto de tu consulta y fragmentos de los tickets que puedes ver se envían a un "
            "proveedor externo de IA para generar la respuesta. No incluyas en tus consultas información que no deba salir de la "
            "entidad. Consulta el Aviso de privacidad para más detalles.",
        ]},
        {"id": "auditoria", "title": "7. Supervisión y registros de auditoría", "blocks": [
            "Para proteger la plataforma y poder revisar lo ocurrido, FixIT registra las acciones relevantes: inicios de sesión "
            "(exitosos y fallidos), cambios en tickets, usuarios y configuración, uso de funciones de IA, consultas y exportaciones "
            "de la auditoría, e intentos de acceso no autorizados. Cada registro incluye fecha y hora, usuario, acción, dirección IP "
            "y navegador.",
            "Solo el Jefe de TI y el Administrador pueden consultar y exportar estos registros, y esas consultas también quedan "
            "registradas. Los registros no pueden modificarse ni eliminarse desde la aplicación.",
        ]},
        {"id": "disponibilidad", "title": "8. Disponibilidad y límites del servicio", "blocks": [
            "La entidad procura que FixIT esté disponible y funcione correctamente, pero pueden existir interrupciones por "
            "mantenimiento, fallas de proveedores o causas externas. Los plazos (SLA) que muestra la plataforma son objetivos "
            f"internos de atención; los compromisos oficiales de servicio son {PENDING}.",
            f"Límites de responsabilidad de la entidad: {PENDING} (requiere redacción y revisión de un especialista legal).",
        ]},
        {"id": "incumplimiento", "title": "9. Incumplimiento", "blocks": [
            "El incumplimiento de estos términos puede dar lugar a la suspensión o desactivación de la cuenta y, cuando "
            f"corresponda, a las medidas previstas en la normativa interna de la entidad ({PENDING}).",
        ]},
        {"id": "cambios", "title": "10. Cambios en estos términos", "blocks": [
            "Cuando estos términos cambien se publicará una nueva versión con su fecha. Si el cambio requiere tu aceptación, "
            "FixIT te lo pedirá al ingresar. Las aceptaciones anteriores se conservan como constancia.",
        ]},
        {"id": "contacto", "title": "11. Ley aplicable y contacto", "blocks": [
            "Estos términos se rigen por las leyes de la República del Perú.",
            f"Consultas sobre estos términos: {PENDING} (correo o canal oficial de la entidad).",
        ]},
    ],
}

PRIVACY = {
    "id": "privacidad",
    "title": "Aviso de privacidad",
    "version": "0.1-borrador",
    "updated": UPDATED,
    "effective": PENDING,
    "requires_acceptance": False,
    "summary": "Qué datos personales usa FixIT, para qué, con quién se comparten, cuánto tiempo se guardan y cómo ejercer tus derechos.",
    "sections": [
        {"id": "aviso", "title": "Antes de empezar", "blocks": [
            "Este aviso explica cómo se tratan tus datos personales en FixIT, de acuerdo con la Ley N.º 29733, Ley de Protección "
            "de Datos Personales, y su reglamento vigente. Es un documento informativo: leerlo no significa que des tu "
            "consentimiento para finalidades adicionales. Si en el futuro se plantea alguna finalidad opcional, se te pedirá "
            "por separado y podrás negarte sin perder el acceso al servicio.",
        ]},
        {"id": "responsable", "title": "1. Responsable del tratamiento", "blocks": [
            {"list": [
                f"Responsable: {PENDING} (denominación o razón social, RUC y domicilio).",
                f"Banco de datos personales y su código de inscripción en el Registro Nacional de Protección de Datos Personales: {PENDING}.",
                f"Contacto para temas de privacidad: {PENDING}.",
            ]},
        ]},
        {"id": "datos", "title": "2. Qué datos usamos", "blocks": [
            {"list": [
                "Datos de identificación y contacto: nombre completo, correo institucional y área.",
                "Datos de acceso: rol y contraseña. La contraseña se guarda cifrada con un algoritmo de un solo sentido (bcrypt); "
                "nadie puede leerla, ni siquiera el personal de TI.",
                "Contenido de las solicitudes: título, descripción, comentarios, archivos adjuntos y calificaciones. Puede incluir "
                "datos personales que tú decidas escribir; te pedimos incluir solo los necesarios.",
                "Datos técnicos y de actividad: fecha y hora de tus acciones, dirección IP, tipo de navegador y resultado de "
                "acciones como el inicio de sesión.",
                "Uso del asistente de IA: el servidor registra que se usó (fecha, resultado), pero no guarda el texto de las "
                "conversaciones. Tu navegador conserva el historial del chat solo mientras la pestaña esté abierta.",
            ]},
            "FixIT no solicita datos sensibles. No los incluyas en tus tickets.",
        ]},
        {"id": "finalidades", "title": "3. Para qué usamos tus datos", "blocks": [
            "Finalidades necesarias para prestar el servicio:",
            {"list": [
                "Crear y administrar tu cuenta y controlar el acceso según tu rol.",
                "Registrar, asignar, atender, cerrar y calificar las solicitudes de soporte, y enviarte notificaciones sobre ellas.",
                "Medir tiempos de atención, cumplimiento de plazos y calidad del servicio, y elaborar reportes internos.",
                "Entrenar y usar modelos estadísticos con el historial de tickets para estimar tiempos y riesgos y sugerir "
                "técnicos o categorías. Estos modelos apoyan al personal; no toman decisiones definitivas sobre ti.",
                "Proteger la plataforma: detectar accesos indebidos, mantener registros de auditoría y atender incidentes de seguridad.",
            ]},
            "Finalidades opcionales: actualmente ninguna.",
            f"Fundamento que habilita el tratamiento (por ejemplo, la relación laboral o contractual con la entidad, o el "
            f"consentimiento): {PENDING}.",
        ]},
        {"id": "destinatarios", "title": "4. Con quién se comparten", "blocks": [
            "Dentro de la entidad, tus datos solo los ven las personas que los necesitan según su rol (ver Términos y condiciones). "
            "Para funcionar, FixIT usa proveedores tecnológicos que tratan datos por encargo de la entidad:",
            {"list": [
                f"Alojamiento de la aplicación (Render) y base de datos (Supabase). Ubicación de los servidores: {PENDING}.",
                "Proveedor del asistente de IA, solo cuando está habilitado (por ejemplo, Google Gemini). Recibe el texto de tu "
                "consulta, el historial reciente del chat y fragmentos de los tickets que puedes ver (título, descripción, estado, "
                f"técnico asignado). Proveedor y condiciones de uso de datos: {PENDING}.",
            ]},
            f"Algunos de estos proveedores pueden estar fuera del Perú, lo que constituye un flujo transfronterizo de datos. "
            f"Garantías aplicadas y comunicación a la autoridad cuando corresponda: {PENDING}.",
        ]},
        {"id": "conservacion", "title": "5. Cuánto tiempo se conservan", "blocks": [
            f"Plazos de conservación de cuentas, tickets, adjuntos, registros de auditoría y copias de respaldo: {PENDING}.",
            "Mientras la entidad no defina estos plazos, FixIT no elimina datos automáticamente. Las cuentas que ya no se usan se "
            "desactivan, lo que impide el acceso pero conserva el historial de los tickets y de la auditoría.",
        ]},
        {"id": "seguridad", "title": "6. Cómo protegemos tus datos", "blocks": [
            {"list": [
                "Conexión cifrada (HTTPS) en el despliegue y contraseñas guardadas con bcrypt.",
                "Control de acceso por rol verificado en el servidor en cada operación.",
                "Bloqueo temporal tras intentos repetidos de inicio de sesión.",
                "Registros de auditoría que no pueden modificarse desde la aplicación y llevan un sello que permite detectar "
                "cambios hechos directamente en la base de datos.",
                "Validación del tipo y tamaño de los archivos adjuntos.",
            ]},
            "Ninguna medida ofrece seguridad absoluta. Si detectas un problema, repórtalo al área de TI. "
            f"Procedimiento de gestión y comunicación de incidentes de seguridad: {PENDING}.",
        ]},
        {"id": "derechos", "title": "7. Tus derechos", "blocks": [
            "Como titular de tus datos puedes solicitar:",
            {"list": [
                "Información y acceso: saber qué datos tuyos se tratan y cómo.",
                "Rectificación: corregir datos inexactos o incompletos.",
                "Cancelación o supresión: pedir que se eliminen cuando ya no sean necesarios o se traten indebidamente.",
                "Oposición: oponerte a un tratamiento por motivos fundados y legítimos.",
                "Los demás derechos que reconozca la normativa vigente.",
            ]},
            f"Cómo ejercerlos: {PENDING} (canal, requisitos de la solicitud y plazos de respuesta según el reglamento vigente).",
            "Si no recibes respuesta o no estás de acuerdo con ella, puedes presentar una reclamación ante la Autoridad Nacional "
            "de Protección de Datos Personales del Ministerio de Justicia y Derechos Humanos.",
        ]},
        {"id": "auditoria", "title": "8. Registros de auditoría y supervisión", "blocks": [
            "FixIT registra las acciones relevantes (inicios de sesión, cambios en tickets y usuarios, uso de IA, consultas y "
            "exportaciones de la auditoría, accesos denegados) con fecha y hora en UTC, usuario, dirección IP y navegador. La "
            "finalidad es la seguridad de la plataforma y la revisión de lo ocurrido. Cualquier otro uso de estos registros "
            f"(por ejemplo, en procedimientos internos): {PENDING}.",
            f"Solo el Jefe de TI y el Administrador pueden consultarlos y exportarlos para auditorías, y esas consultas también "
            f"se registran. Los registros no incluyen contraseñas, tokens ni claves. Plazo de conservación: {PENDING}.",
        ]},
        {"id": "almacenamiento", "title": "9. Cookies y almacenamiento en tu navegador", "blocks": [
            "FixIT no usa cookies. Para mantener tu sesión guarda dos credenciales temporales en el almacenamiento local del "
            "navegador, que se borran al cerrar sesión. El historial del asistente se guarda en el almacenamiento de la pestaña "
            "y se borra al cerrarla.",
        ]},
        {"id": "cambios", "title": "10. Cambios en este aviso", "blocks": [
            "Publicaremos aquí cualquier cambio, con su versión y fecha. Si un cambio implica una nueva finalidad que requiera "
            "tu consentimiento, te lo pediremos expresamente.",
        ]},
    ],
}

DOCUMENTS = {TERMS["id"]: TERMS, PRIVACY["id"]: PRIVACY}

# Shown on the legal pages while the documents are drafts.
REVIEW_NOTE = {
    "title": "Borrador pendiente de validación",
    "text": "Estos documentos son un borrador técnico. La entidad responsable y un especialista legal deben completar los "
            "datos marcados como pendientes y revisar el contenido antes de su aprobación. Su publicación no acredita por "
            "sí sola el cumplimiento de la Ley N.º 29733 ni de su reglamento.",
    "checklist": [
        "Identidad del responsable, RUC, domicilio y contacto de privacidad.",
        "Fundamento del tratamiento (relación laboral o contractual, consentimiento u otro) para cada finalidad.",
        "Inscripción del banco de datos en el Registro Nacional de Protección de Datos Personales.",
        "Plazos de conservación y procedimiento de eliminación o anonimización.",
        "Proveedores encargados, ubicación de servidores y garantías para el flujo transfronterizo (Render, Supabase, proveedor de IA).",
        "Canal, requisitos y plazos para el ejercicio de derechos según el reglamento vigente.",
        "Procedimiento de gestión y comunicación de incidentes de seguridad.",
        "Límites de responsabilidad, niveles de servicio y régimen disciplinario aplicable.",
    ],
}


def public_documents() -> dict:
    return {"documents": list(DOCUMENTS.values()), "review_note": REVIEW_NOTE, "pending_marker": PENDING}
