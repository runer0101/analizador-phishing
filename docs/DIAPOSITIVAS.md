# Diapositivas — Analizador de phishing (1 a 5)

Cinco diapositivas para los primeros 5:30 de la exposición. Lo que se dice está en
[`GUION.md`](GUION.md); las diapositivas 6 a 10 (honeypot, defensa y cierre) están en el
repositorio `honeypot-casero`.

---

## 1 · Portada

**Phishing y honeypot: dos herramientas propias para ver el ataque y la defensa**

- Rust, sin dependencias externas, sin internet
- Actividad de ciberseguridad — 5 de diciembre de 2026

---

## 2 · El problema

- El phishing ya no necesita software: necesita prisa y confianza
- `paypa1.com` se ve como PayPal si uno mira rápido
- Dos formas de defender: **analizar antes** y **observar después**

---

## 3 · Herramienta 1 — el analizador

- Lee el enlace **como texto**: no lo visita, no pide DNS, no sale a internet
- Once reglas, cada una con un puntaje
- 5+ puntos → **ALTO** · 3-4 → **MEDIO** · 0-2 → **BAJO**

```
🔴 ALTO — 5 pts, 3 señales
  http://paypa1.com/login/verify
    +1  no_https    No usa HTTPS: el tráfico puede interceptarse
    +1  hook_words  Palabra de gancho: «login»
    +3  typosquat   Imita a paypal.com (typosquatting)
```

---

## 4 · Las señales en una línea

| Señal | Puntos | Detecta |
| --- | --- | --- |
| `no_https` | 1 | sin HTTPS |
| `ip_host` | 2 | IP en vez de dominio |
| `userinfo` | 2 | el `«@»` que esconde el destino |
| `deep_subdomain` | 1 | demasiados subdominios |
| `punycode` | 2 | letras camufladas |
| `shortener` | 2 | destino oculto |
| `suspicious_tld` | 1 | `.xyz`, `.top`, … |
| `hyphen_chain` | 1 | muchos guiones |
| `hook_words` | 1 | `login`, `clave`, `verificar`… |
| `brand_impersonation` | 3 | marca que no es la oficial |
| `typosquat` | 3 | marca imitada (`paypa1`) |

---

## 5 · Lo que el analizador NO puede hacer

- **Falsos positivos**: un sitio real con `verificacion` en la ruta suma un punto
- **Falsos negativos**: un phishing con dominio limpio puede salir en verde
- **Solo mira la dirección**: no ve la página

> Conclusión correcta: «esto **merece revisión humana**», no «esto es phishing».
