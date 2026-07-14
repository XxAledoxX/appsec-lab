# XSS Reflejado en `/search` (GET)

| | |
|---|---|
| **Severidad** | High |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation |
| **OWASP Top 10 (2021)** | A03:2021 — Injection |
| **Ruta afectada** | `GET /search?q=` |
| **Componente** | `vulnshop/app.py:28-34` |
| **Estado** | Abierta (intencional — objetivo del lab) |

## Descripción

El parámetro `q` de `/search` se refleja en la respuesta HTML sin ningún filtrado. Jinja2 escapa por defecto todo lo que se interpola en una plantilla, pero el código envuelve explícitamente el valor en `markupsafe.Markup()`, que **desactiva ese auto-escape** y le dice al motor de plantillas "esto ya es HTML seguro, insértalo tal cual".

## Impacto

Cualquier atacante puede construir una URL con JavaScript embebido en `q` y compartirla (phishing, enlace acortado, campaña de email). Si una víctima autenticada la abre, el script se ejecuta en su sesión: robo de cookies (si no fueran `HttpOnly`, ver [[04-insecure-cookies]]), pivote a acciones en nombre del usuario, o keylogging del formulario de login.

## Prueba de concepto (PoC)

```
GET /search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E HTTP/1.1
Host: localhost:5000
```

Respuesta (fragmento):

```html
<p>Resultados para: <script>alert(document.cookie)</script></p>
```

El script se ejecuta al renderizar la página — sin necesidad de interacción adicional.

Detectado automáticamente por `dast_scanner.py`, Módulo 1 (`check_xss_get`), que prueba varios payloads (`<script>`, `<img onerror>`, `<svg onload>`) y confirma que se reflejan sin escapar.

## Causa raíz

```python
# vulnshop/app.py
@app.route("/search")
def search():
    query = request.args.get("q", "")
    safe_query = Markup(query)          # ← desactiva el auto-escape de Jinja2
    return render_template("search.html", query=safe_query)
```

`Markup()` sobre un string **no confiable** es el antipatrón exacto que produce XSS en apps Flask/Jinja2 — es fácil de introducir sin darse cuenta porque el nombre de la clase suena "seguro".

## Remediación

- Eliminar el `Markup()` y dejar que Jinja2 escape por defecto: `render_template("search.html", query=query)`.
- Si de verdad se necesita renderizar HTML controlado por el usuario (raro), usar una librería de sanitización como `bleach` con una allowlist de tags/atributos, nunca `Markup()` directo sobre input.
- Añadir una Content-Security-Policy (ver [[07-missing-security-headers]]) como capa de defensa en profundidad, aunque no sustituye el escapado correcto.

## Referencias

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Flask/Jinja2 — Markup safety](https://flask.palletsprojects.com/en/latest/templating/#jinja-setup)
