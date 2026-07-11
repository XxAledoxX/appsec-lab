# XSS Reflejado en `/comment` (POST)

| | |
|---|---|
| **Severidad** | High |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation |
| **OWASP Top 10 (2021)** | A03:2021 — Injection |
| **Ruta afectada** | `POST /comment` (campos `name`, `message`) |
| **Componente** | `vulnshop/app.py:37-45` |
| **Estado** | Abierta (intencional — objetivo del lab) |

## Descripción

Igual que en `/search` ([[01-xss-reflected-search]]), pero por `POST` y en dos puntos de inyección independientes: `name` y `message`. Ambos campos se envuelven en `Markup()` antes de pasarlos a la plantilla, desactivando el auto-escape de Jinja2 en ambos.

## Impacto

Al no requerir un enlace especial (basta con enviar el formulario), esta variante es explotable también mediante un **CSRF que auto-envíe el formulario** desde un sitio de terceros, ya que la app no implementa protección CSRF. El script se ejecuta para cualquier usuario que visite la página de comentarios después del envío (XSS "stored-like" si los comentarios se listaran a otros usuarios; aquí es reflejado, pero el patrón de riesgo es el mismo).

## Prueba de concepto (PoC)

```
POST /comment HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded

name=Ana&message=<script>alert(document.cookie)</script>
```

Respuesta (fragmento):

```html
<h3>Comentario de: Ana</h3>
<p><script>alert(document.cookie)</script></p>
```

Detectado automáticamente por `dast_scanner.py`, Módulo 2 (`check_xss_post`), que inyecta cada payload en cada campo del formulario por separado.

## Causa raíz

```python
# vulnshop/app.py
@app.route("/comment", methods=["GET", "POST"])
def comment():
    result = None
    if request.method == "POST":
        name = Markup(request.form.get("name", ""))       # ← sin escapar
        message = Markup(request.form.get("message", "")) # ← sin escapar
        result = {"name": name, "message": message}
    return render_template("comment.html", result=result)
```

## Remediación

- Quitar `Markup()` de ambos campos; dejar el auto-escape de Jinja2 activo.
- Añadir protección CSRF (p.ej. `flask-wtf` con tokens) para que un formulario de terceros no pueda enviar comentarios en nombre de la víctima.
- Si el proyecto evolucionara a comentarios persistentes (BBDD), sanitizar también en el punto de almacenamiento y al mostrarlos a otros usuarios (ahí sí sería Stored XSS, CWE-79 con impacto mayor).

## Referencias

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
