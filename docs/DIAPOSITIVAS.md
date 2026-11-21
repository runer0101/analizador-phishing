# Diapositivas — Analizador de phishing (1 a 5)

Cinco diapositivas para los primeros 5:30 de la exposición. Lo que se dice está en
[`GUION.md`](GUION.md); las diapositivas 6 a 10 (honeypot, defensa y cierre) están en el
repositorio `honeypot-casero`.

---

## 1 · Portada

**Phishing y honeypot: dos herramientas propias para ver el ataque y la defensa**

- Rust, sin dependencias externas, sin internet
- Herramientas propias de ciberseguridad, escritas en Rust

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
- **Demo en vivo:** https://runer0101.github.io/analizador-phishing/

```
🔴 ALTO — 5 pts, 3 señales
  http://paypa1.com/login/verify
    +1  sin_https       No usa HTTPS: el tráfico puede interceptarse
    +1  palabra_gancho  Palabra de gancho: «login»
    +3  typosquatting   Imita a paypal.com con una diferencia mínima
```

---

## 4 · Las señales en una línea

| Señal | Código | Puntos | Detecta |
| --- | --- | --- | --- |
| No usa HTTPS | `sin_https` | 1 | Sin HTTPS |
| IP en lugar de dominio | `ip_dominio` | 2 | IP en vez de dominio (también decimal, hex. u octal) |
| El «@» que esconde el destino | `usuario_oculto` | 2 | El dominio real está detrás de otro |
| Demasiados subdominios | `subdominios` | 1 | El dominio real está al final |
| Letras camufladas | `letras_camufladas` | 2 | Punycode o letras no latinas |
| Link acortado | `acortador` | 2 | Destino oculto |
| Terminación poco confiable | `terminacion_rara` | 1 | `.xyz`, `.top`, … |
| Muchos guiones | `guiones` | 1 | Patrón de suplantación |
| Palabra de gancho | `palabra_gancho` | 1 | `login`, `clave`, `verificar`… |
| Usa el nombre de una marca | `marca_falsa` | 3 | Marca que no es la oficial |
| Imita a una marca | `typosquatting` | 3 | Un cambio de diferencia (de más, de menos, cambiada) |

---

## 5 · Lo que el analizador NO puede hacer

- **Falsos positivos**: un sitio real con `verificacion` en la ruta suma un punto
- **Falsos negativos**: un phishing con dominio limpio puede salir en verde
- **Solo mira la dirección**: no ve la página

> Conclusión correcta: «esto **merece revisión humana**», no «esto es phishing».
