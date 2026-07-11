# Ausencia de headers de seguridad

| | |
|---|---|
| **Severidad** | Low |
| **CWE** | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) — Protection Mechanism Failure |
| **OWASP Top 10 (2021)** | A05:2021 — Security Misconfiguration |
| **Ruta afectada** | Todas las rutas |
| **Componente** | `vulnshop/app.py` (ninguna configuración de headers de seguridad) |
| **Estado** | Abierta (intencional — objetivo del lab) |

## Descripción

Ninguna respuesta incluye headers de seguridad estándar. El scanner verifica la ausencia de:

- `Content-Security-Policy` — mitiga XSS restringiendo qué scripts/recursos puede cargar la página.
- `X-Frame-Options` — previene clickjacking (embeber el sitio en un `<iframe>` malicioso).
- `Strict-Transport-Security` (HSTS) — fuerza HTTPS en visitas futuras.
- `X-Content-Type-Options: nosniff` — evita que el navegador reinterprete el `Content-Type` declarado.
- `Referrer-Policy` — controla qué se filtra en el header `Referer` hacia sitios externos.

## Impacto

Cada header ausente es una capa de defensa en profundidad menos. Por sí solos no crean una vulnerabilidad explotable directamente, pero **amplifican el impacto de los otros hallazgos**: sin CSP, los XSS de este lab ([[01-xss-reflected-search]], [[02-xss-reflected-comment]]) no tienen ninguna mitigación adicional; sin `X-Frame-Options`, el sitio es embebible en un iframe para ataques de clickjacking sobre el formulario de login.

## Prueba de concepto (PoC)

```
GET / HTTP/1.1
Host: localhost:5000
```

Respuesta — headers de seguridad ausentes (verificar con `curl -I`):

```
$ curl -sI http://localhost:5000/ | grep -iE "content-security|x-frame|strict-transport|x-content-type|referrer-policy"
# (sin resultados)
```

Detectado automáticamente por `dast_scanner.py`, Módulo 7 (`check_missing_security_headers`).

## Causa raíz

La app no define ningún middleware ni hook `after_request` que añada estos headers (el único hook existente añade los headers falsos de [[06-information-disclosure]]).

## Remediación

```python
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

En producción, una librería como [`flask-talisman`](https://github.com/GoogleCloudPlatform/flask-talisman) aplica un set razonable de estos headers por defecto sin tener que mantenerlos a mano.

## Referencias

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN — CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
