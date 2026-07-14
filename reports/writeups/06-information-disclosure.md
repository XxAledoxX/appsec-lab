# Information Disclosure vía headers `Server` / `X-Powered-By`

| | |
|---|---|
| **Severidad** | Low |
| **CWE** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) — Exposure of Sensitive Information to an Unauthorized Actor |
| **OWASP Top 10 (2021)** | A05:2021 — Security Misconfiguration |
| **Ruta afectada** | Todas las rutas |
| **Componente** | `vulnshop/app.py:15-20` (`add_fake_server_headers`) |
| **Estado** | Abierta (intencional — objetivo del lab) |

## Descripción

Un hook `after_request` añade a **todas** las respuestas los headers `Server: Apache/2.2.14 (Win32)` y `X-Powered-By: PHP/5.3.3`. En el lab son valores falsos puestos a propósito para simular fingerprinting; en una app real, el equivalente sería no desactivar los headers por defecto del servidor/framework (Werkzeug expone su propia versión si no se sobreescribe).

## Impacto

Por sí solo es Low: no compromete nada directamente. Pero facilita el **reconocimiento** de un atacante — versión de servidor/lenguaje concretas permiten buscar CVEs conocidos y afinar el ataque, reduciendo el "ruido" necesario para encontrar la superficie vulnerable real.

## Prueba de concepto (PoC)

```
GET / HTTP/1.1
Host: localhost:5000
```

Respuesta (fragmento):

```
Server: Apache/2.2.14 (Win32)
X-Powered-By: PHP/5.3.3
```

Detectado automáticamente por `dast_scanner.py`, Módulo 6 (`check_info_disclosure`).

## Causa raíz

```python
# vulnshop/app.py
@app.after_request
def add_fake_server_headers(response):
    response.headers["Server"] = "Apache/2.2.14 (Win32)"
    response.headers["X-Powered-By"] = "PHP/5.3.3"
    return response
```

## Remediación

- No añadir headers que revelen tecnología/versión. En Flask/Werkzeug real, sobreescribir o eliminar el header `Server` por defecto en el servidor WSGI de producción (gunicorn, nginx delante) en vez de exponerlo.
- Auditar periódicamente las respuestas con herramientas como este mismo scanner para detectar fugas de información no intencionadas al añadir middlewares o proxies nuevos.

## Referencias

- [OWASP Testing for Web Server Fingerprint (WSTG-INFO-02)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
