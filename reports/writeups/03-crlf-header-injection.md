# CRLF / Header Injection en `/login` y `/newsletter`

| | |
|---|---|
| **Severidad** | High |
| **CWE** | [CWE-113](https://cwe.mitre.org/data/definitions/113.html) — Improper Neutralization of CRLF Sequences in HTTP Headers |
| **OWASP Top 10 (2021)** | A03:2021 — Injection |
| **Ruta afectada** | `POST /login` (campo `username`), `POST /newsletter` (campo `lang`) |
| **Componente** | `vulnshop/app.py:48-58` y `:71-80` |
| **Estado** | Abierta (intencional — objetivo del lab) |

## Descripción

Ambos endpoints copian un valor de formulario directamente a un header de respuesta HTTP (`X-Logged-User` y `Content-Language` respectivamente) sin sanitizar secuencias `\r\n`. Si el servidor no las neutraliza, un atacante puede inyectar headers adicionales o, en escenarios más antiguos (proxies, versiones de servidor vulnerables), partir la respuesta HTTP (**HTTP Response Splitting**) para inyectar contenido arbitrario en el cuerpo de la respuesta que ve la víctima.

En despliegues modernos de Werkzeug/Flask, el propio servidor bloquea literales `\r\n` en el valor del header (lanza `ValueError`) — pero el **punto de inyección sin sanitizar en el código de la aplicación sigue existiendo**, y es explotable si la app se sirve detrás de un proxy/gateway más permisivo o en una versión antigua del stack.

## Impacto

- Inyección de headers arbitrarios (`Set-Cookie` falso, cabeceras de caché, `Location`) → fijación de sesión, cache poisoning, redirecciones no autorizadas.
- Response splitting → inyección de contenido controlado por el atacante en la respuesta (defacement, XSS vía cuerpo inyectado) si el stack subyacente no filtra.

## Prueba de concepto (PoC)

```
POST /login HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded

username=admin%0d%0aX-Injected: pwned&password=x
```

Comportamiento esperado en un stack vulnerable: el header de respuesta incluye `X-Injected: pwned` como header independiente.

En el stack actual (Werkzeug reciente), el servidor rechaza el CRLF crudo en el header, pero `dast_scanner.py` (Módulo 3, `check_crlf_injection`) detecta igualmente que **el valor llega sin sanitizar hasta el punto de construcción del header** — el bug de diseño está en la aplicación, no en el servidor.

## Causa raíz

```python
# vulnshop/app.py — /login
response.headers["X-Logged-User"] = username   # ← input crudo del usuario en un header

# vulnshop/app.py — /newsletter
response.headers["Content-Language"] = lang     # ← mismo patrón
```

## Remediación

- Nunca escribir input de usuario directamente en un header de respuesta.
- Si es imprescindible reflejar un valor en un header, validarlo contra una allowlist estricta (p.ej. `lang` contra códigos ISO 639-1 conocidos) y rechazar cualquier carácter de control (`\r`, `\n`, `%0d`, `%0a`).
- Preferir no exponer datos de sesión en headers custom; usar cookies firmadas o el propio `session` de Flask.

## Referencias

- [OWASP CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [CWE-113](https://cwe.mitre.org/data/definitions/113.html)
