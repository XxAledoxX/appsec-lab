# Findings Summary — AppSec Lab

## SAST — Análisis estático con Bandit sobre OWASP PyGoat

| Severidad | Hallazgos |
|-----------|-----------|
| HIGH      | 6         |
| MEDIUM    | 2         |
| LOW       | 3         |

### Hallazgos destacados

| ID | CWE | Severidad | Descripción |
|----|-----|-----------|-------------|
| B303 | CWE-327 | HIGH | MD5 para generación de tokens — algoritmo roto criptográficamente |
| B303 | CWE-916 | HIGH | MD5 para hashing de contraseñas — debe usarse bcrypt/argon2 |
| B602 | CWE-78  | HIGH | `subprocess` con `shell=True` + input de usuario → Command Injection |
| B105 | CWE-798 | HIGH | Clave secreta hardcodeada en settings.py |
| B501 | CWE-295 | MEDIUM | `requests.get(verify=False)` → vulnerable a MITM |

---

## DAST — Análisis dinámico sobre VulnShop

### Hallazgos por módulo

| Módulo | Severidad | Ruta | Detalle |
|--------|-----------|------|---------|
| XSS Reflected (GET) | HIGH | `/search?q=` | Input reflejado sin escapar via `Markup()` |
| XSS Reflected (POST) | HIGH | `/comment` | Campos `name` y `message` sin sanitizar |
| CRLF Injection | HIGH | `/login` | Campo `username` inyectado en header `X-Logged-User` |
| CRLF Injection | HIGH | `/newsletter` | Campo `lang` inyectado en header `Content-Language` |
| Open Redirect | HIGH | `/redirect?url=` | Redirige a dominios externos sin validación |
| Insecure Cookie | MEDIUM | `/profile` | Cookie `session_user` sin `HttpOnly`, `Secure`, `SameSite` |
| Information Disclosure | LOW | Todas | `Server: Apache/2.2.14`, `X-Powered-By: PHP/5.3.3` |
| Missing Security Headers | LOW | Todas | Ausentes: CSP, X-Frame-Options, HSTS, X-Content-Type-Options |

### Herramientas utilizadas
- **Bandit** v1.7.x — análisis estático Python
- **dast_scanner.py** — scanner black-box custom (7 módulos)
- **Wapiti3** — crawler + scanner automático
- **OWASP ZAP** — análisis dinámico con interfaz gráfica

### Metodología
1. SAST sobre código fuente (PyGoat) para detectar vulnerabilidades sin ejecutar la aplicación
2. Despliegue local de VulnShop en entorno controlado
3. DAST black-box con scanner propio para validar las vulnerabilidades en runtime
4. Verificación manual de hallazgos con herramientas especializadas (Wapiti3, ZAP)

### Writeups detallados

Cada hallazgo de VulnShop tiene un informe individual en [`reports/writeups/`](writeups/), con PoC (request/response), causa raíz en el código y remediación:

- [XSS Reflected (GET) — `/search`](writeups/01-xss-reflected-search.md)
- [XSS Reflected (POST) — `/comment`](writeups/02-xss-reflected-comment.md)
- [CRLF / Header Injection — `/login`, `/newsletter`](writeups/03-crlf-header-injection.md)
- [Open Redirect — `/redirect`](writeups/04-open-redirect.md)
- [Insecure Cookie — `/profile`](writeups/05-insecure-cookies.md)
- [Information Disclosure](writeups/06-information-disclosure.md)
- [Missing Security Headers](writeups/07-missing-security-headers.md)
