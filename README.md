# appsec-lab

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
![License](https://img.shields.io/badge/license-MIT-green)

> **Laboratorio de Application Security**: aplicación web intencionalmente vulnerable (VulnShop) + escáner DAST custom de 7 módulos + análisis SAST con Bandit.

---

## Contenido

```
appsec-lab/
├── vulnshop/           # App Flask con vulnerabilidades OWASP Top 10 intencionales
│   ├── app.py
│   └── templates/
├── dast_scanner/
│   └── dast_scanner.py # Escáner black-box con 7 módulos de detección
├── sast/
│   └── bandit_report.json
└── reports/
    └── findings_summary.md
```

---

## VulnShop — Vulnerabilidades implementadas

| Ruta | Vulnerabilidad | CWE |
|------|---------------|-----|
| `GET /search?q=` | XSS Reflected | CWE-79 |
| `POST /comment` | XSS Reflected (POST) | CWE-79 |
| `POST /login` | CRLF / Header Injection | CWE-113 |
| `GET /redirect?url=` | Open Redirect + CRLF | CWE-601 |
| `POST /newsletter` | Header Injection | CWE-113 |
| `GET /profile` | Insecure Cookie | CWE-614 |
| Todas las rutas | Information Disclosure | CWE-200 |
| Todas las rutas | Missing Security Headers | CWE-693 |

### Levantar VulnShop

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python vulnshop/app.py
# → http://localhost:5000
```

---

## DAST Scanner

Escáner black-box en Python con 7 módulos de detección. Genera reporte HTML y JSON.

### Módulos

| # | Módulo | Técnica |
|---|--------|---------|
| 1 | XSS Reflected (GET) | Inyección de payloads en parámetros GET |
| 2 | XSS Reflected (POST) | Inyección en campos de formularios |
| 3 | CRLF / Header Injection | Inyección de `\r\n` en inputs de cabeceras |
| 4 | Open Redirect | Envío de URLs externas en parámetro de redirección |
| 5 | Insecure Cookies | Verificación de flags HttpOnly, Secure, SameSite |
| 6 | Information Disclosure | Detección de `Server` y `X-Powered-By` expuestos |
| 7 | Missing Security Headers | Comprueba CSP, X-Frame-Options, HSTS, X-Content-Type-Options |

### Uso

```bash
# Con VulnShop corriendo en localhost:5000
python dast_scanner/dast_scanner.py --url http://localhost:5000

# Reportes generados:
#   reports/dast_report.html
#   reports/dast_report.json
```

### Ejemplo de salida

```
[*] DAST Scanner iniciado — target: http://localhost:5000

[*] Módulo 1 — XSS Reflected (GET)
  [HIGH] XSS reflejado en /search (param: q)

[*] Módulo 4 — Open Redirect
  [HIGH] Open Redirect — redirección a dominio externo sin validación

[*] Módulo 5 — Insecure Cookies
  [MED ] Set-Cookie header inseguro: sin HttpOnly, sin Secure, sin SameSite

[*] Módulo 6 — Information Disclosure
  [LOW ] Header 'Server' revela tecnología: Apache/2.2.14 (Win32)
  [LOW ] Header 'X-Powered-By' revela tecnología: PHP/5.3.3

[*] Escaneo completado. Hallazgos: 12
```

---

## SAST — Análisis estático con Bandit

Análisis realizado sobre **OWASP PyGoat** como objetivo de práctica.

### Hallazgos principales (6 HIGH)

| Test | CWE | Descripción |
|------|-----|-------------|
| B303 | CWE-327 | MD5 para generación de tokens — criptográficamente roto |
| B303 | CWE-916 | MD5 para hashing de contraseñas — debe ser bcrypt/argon2 |
| B602 | CWE-78  | `subprocess` con `shell=True` + input usuario → Command Injection |
| B105 | CWE-798 | Clave secreta hardcodeada en código fuente |

Ver reporte completo: [`sast/bandit_report.json`](sast/bandit_report.json)

---

## Disclaimer

> Este proyecto es **exclusivamente educativo**. VulnShop contiene vulnerabilidades intencionales diseñadas para prácticas de seguridad en entornos locales controlados.  
> **No desplegar en producción ni en sistemas accesibles públicamente.**  
> El uso de las herramientas incluidas contra sistemas sin autorización explícita es ilegal.
