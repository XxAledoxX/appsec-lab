# appsec-lab

[![CI](https://github.com/XxAledoxX/appsec-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/XxAledoxX/appsec-lab/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
![License](https://img.shields.io/badge/license-MIT-green)

> **Laboratorio de Application Security**: aplicación web intencionalmente vulnerable (VulnShop) + escáner DAST custom de 7 módulos + análisis SAST con Bandit, con **pipeline de CI que ejecuta tests, SAST y un DAST end-to-end** en cada push.

---

## Quickstart

```bash
make install     # crea .venv e instala dependencias
make run         # levanta VulnShop en http://localhost:5000
make scan        # (en otra terminal) lanza el DAST scanner contra VulnShop
make test        # ejecuta la suite de pytest
```

---

## Contenido

```
appsec-lab/
├── .github/workflows/
│   └── ci.yml          # Pipeline CI: tests + SAST (Bandit) + DAST end-to-end
├── vulnshop/           # App Flask con vulnerabilidades OWASP Top 10 intencionales
│   ├── app.py
│   └── templates/
├── dast_scanner/
│   └── dast_scanner.py # Escáner black-box con 7 módulos de detección
├── tests/
│   └── test_dast_scanner.py  # Tests (incl. regresión anti-XSS del reporte)
├── sast/
│   └── bandit_report.json
├── reports/
│   └── findings_summary.md
├── Makefile
└── requirements.txt / requirements-dev.txt
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

# Gate para CI: sale con código != 0 si hay hallazgos HIGH o superiores
python dast_scanner/dast_scanner.py --url http://localhost:5000 --fail-on HIGH

# Reportes generados:
#   reports/dast_report.html   (con resumen por severidad, output escapado)
#   reports/dast_report.json   (incluye severity_summary)
```

**Opciones:** `--url` (target), `--json`/`--html` (rutas de salida), `--fail-on {HIGH,MEDIUM,LOW,INFO,none}` (exit code para integración en CI).

### Ejemplo de salida

```
[*] DAST Scanner iniciado — target: http://localhost:5000

[*] Módulo 1 — XSS Reflected (GET)
  [HIGH] XSS reflejado en /search (param: q)

[*] Módulo 4 — Open Redirect
  [HIGH] Open Redirect — redirección a dominio externo sin validación

[*] Módulo 5 — Insecure Cookies
  [MED]  Set-Cookie header inseguro: sin HttpOnly, sin Secure, sin SameSite

[*] Módulo 6 — Information Disclosure
  [LOW]  Header 'Server' revela tecnología: Apache/2.2.14 (Win32)
  [LOW]  Header 'X-Powered-By' revela tecnología: PHP/5.3.3

[*] Escaneo completado. Hallazgos: 15  (HIGH: 6  MEDIUM: 2  LOW: 7  INFO: 0)
```

> **Nota de diseño:** el generador de reportes escapa todos los valores controlados por el input (URLs, evidencia, payloads) con `html.escape()`. Sin esto, un payload como `<script>` incrustado en un hallazgo convertiría el propio reporte HTML en vector de XSS al abrirlo — un fallo común en herramientas de seguridad caseras. Hay un test de regresión que lo cubre.

---

## Testing y CI

```bash
make test    # pytest tests/ -q
```

El workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) ejecuta en cada push/PR:

1. **Tests** — `pytest` (lógica de reporte + regresión anti-XSS).
2. **SAST** — Bandit sobre el scanner (debe estar limpio, `-ll`) e informativo sobre VulnShop.
3. **DAST end-to-end** — levanta VulnShop, lanza el scanner y verifica que detecta las vulnerabilidades HIGH intencionales; sube el reporte como artefacto.

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
