# Cookie insegura en `/profile`

| | |
|---|---|
| **Severidad** | Medium |
| **CWE** | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) — Sensitive Cookie Without 'Secure' Attribute (y ausencia de `HttpOnly`/`SameSite`) |
| **OWASP Top 10 (2021)** | A05:2021 — Security Misconfiguration |
| **Ruta afectada** | `GET /profile` |
| **Componente** | `vulnshop/app.py:83-89` |
| **Estado** | Abierta (intencional — objetivo del lab) |

## Descripción

La cookie `session_user` se establece con `response.set_cookie(name, value)` sin ninguno de los tres flags de seguridad recomendados:

- **`HttpOnly`** ausente → accesible desde JavaScript (`document.cookie`), lo que la convierte en objetivo directo de cualquier XSS del sitio (ver [[01-xss-reflected-search]], [[02-xss-reflected-comment]]).
- **`Secure`** ausente → se enviaría también por HTTP plano si la app se sirviera sin TLS, exponiéndola a interceptación en redes no confiables.
- **`SameSite`** ausente → el navegador la adjunta en peticiones cross-site, ampliando la superficie de CSRF.

## Impacto

Combinada con cualquiera de los XSS del lab, esta cookie es robable con un simple `document.cookie` desde el payload inyectado, permitiendo secuestro de sesión. Aislada, ya es una mala práctica que un escáner de cumplimiento (o un cliente en una auditoría) señalaría.

## Prueba de concepto (PoC)

```
GET /profile HTTP/1.1
Host: localhost:5000
```

Respuesta (fragmento):

```
Set-Cookie: session_user=invitado
```

Sin `HttpOnly; Secure; SameSite=Strict`. Verificable también en DevTools → Application → Cookies, donde la columna `HttpOnly` aparece vacía.

Detectado automáticamente por `dast_scanner.py`, Módulo 5 (`check_insecure_cookies`), que inspecciona tanto el objeto `Cookie` parseado por `requests` como el header `Set-Cookie` crudo.

## Causa raíz

```python
# vulnshop/app.py
response.set_cookie("session_user", user)   # ← sin httponly=True, secure=True, samesite=...
```

## Remediación

```python
response.set_cookie(
    "session_user", user,
    httponly=True,
    secure=True,       # requiere servir sobre HTTPS
    samesite="Strict",
)
```

En producción, además: usar `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SECURE` y `SESSION_COOKIE_SAMESITE` en la config de Flask para que aplique a la cookie de sesión nativa, y forzar HTTPS con HSTS (ver [[07-missing-security-headers]]).

## Referencias

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN — Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
