# Open Redirect en `/redirect`

| | |
|---|---|
| **Severidad** | High |
| **CWE** | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) — URL Redirection to Untrusted Site |
| **OWASP Top 10 (2021)** | A01:2021 — Broken Access Control |
| **Ruta afectada** | `GET /redirect?url=` |
| **Componente** | `vulnshop/app.py:61-68` |
| **Estado** | Abierta (intencional — objetivo del lab) |

## Descripción

El parámetro `url` se copia sin validación al header `Location` de una respuesta 302. No hay comprobación de que el destino pertenezca al propio dominio (allowlist) ni de que sea una ruta relativa — cualquier URL absoluta a un dominio externo es aceptada.

## Impacto

Un enlace con apariencia legítima (`https://vulnshop.example.com/redirect?url=...`) puede redirigir a un sitio de phishing controlado por el atacante. Es un vector clásico para campañas de phishing que abusan de la confianza en el dominio real, y también facilita el robo de tokens OAuth si el flujo de autorización usa redirects sin validar.

## Prueba de concepto (PoC)

```
GET /redirect?url=https://evil.com HTTP/1.1
Host: localhost:5000
```

Respuesta:

```
HTTP/1.1 302 FOUND
Location: https://evil.com
```

También es vulnerable a variantes de bypass de filtros ingenuos, como `//evil.com` (protocol-relative, muchos navegadores lo tratan como externo) o `https://evil.com%2F@localhost` (confusión de userinfo en la URL). `dast_scanner.py` (Módulo 4, `check_open_redirect`) prueba las tres variantes.

## Causa raíz

```python
# vulnshop/app.py
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    response = make_response("", 302)
    response.headers["Location"] = url   # ← sin validar dominio ni esquema
    return response
```

## Remediación

- Mantener una **allowlist** de destinos permitidos (rutas relativas propias, o un conjunto cerrado de dominios de confianza) y rechazar cualquier otro valor.
- Si se necesita soportar redirects "vuelve a donde estabas", usar tokens opacos que mapeen a una URL interna conocida, en vez de aceptar la URL completa como parámetro.
- Validar explícitamente que la URL no sea protocol-relative (`//...`) ni contenga `@` antes del host real.

## Referencias

- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601](https://cwe.mitre.org/data/definitions/601.html)
