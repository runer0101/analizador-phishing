# Guion — Analizador de phishing (parte 1 de la actividad)

Tiempo: **0:00 a 5:30** de los 12 minutos de la exposición. La segunda mitad (el honeypot)
está en el repositorio `honeypot-casero`, y el guion completo de las dos partes está en
[`PRESENTACION.md`](PRESENTACION.md).

Los comandos son los mismos que usa `scripts/demo.sh`.

---

## 0:00 — 1:00 · Portada

**Diapositiva 1.**

> «Voy a mostrar dos herramientas que escribí en Rust para esta actividad: una detecta
> enlaces de phishing **sin visitarlos** y la otra es un honeypot que **graba lo que hace
> un atacante** cuando entra. Las dos corren en mi máquina, sin internet, y están escritas
> sin usar ninguna biblioteca externa: solo la biblioteca estándar de Rust.»

---

## 1:00 — 2:30 · El problema

**Diapositiva 2.**

> «El phishing sigue funcionando porque ya no necesita software: necesita que **yo** tenga
> prisa y confianza. Un enlace como `paypa1.com` se ve como PayPal si uno mira rápido: es la
> "l" cambiada por un "1".»

> «Hay dos formas de defender. Una es analizar el enlace **antes** de que la persona lo
> abra. La otra es **observar al atacante** cuando entra, para saber qué busca. Eso es
> justamente lo que hacen las dos herramientas que les voy a mostrar.»

---

## 2:30 — 4:30 · El analizador de phishing

**Ejecutar:**

```bash
target/release/phishing-analyzer --demo
```

**Diapositiva 3.** Mientras corre, explicar en voz alta:

> «El analizador **no abre el enlace**. No pide DNS, no hace peticiones, no sale a
> internet. Toma el texto del enlace y le aplica once reglas, cada una con un puntaje. Al
> final suma los puntos: cinco o más es riesgo alto, tres o cuatro medio, menos de tres
> bajo.»

Señalar en pantalla, uno por uno:

| Lo que se ve | Lo que significa |
| --- | --- |
| `+3 typosquat` | el «1» de `paypa1` imita la «l» de PayPal |
| `+3 brand_impersonation` | dice "paypal" pero el dominio real termina en `.com` |
| `+2 ip_host` | un login de WordPress servido desde una IP cruda |
| `+1 hook_words` | palabras de gancho: `login`, `verify`, `clave`… |

> «Fíjense en el último caso: `bancounion.com.bo` **es** un sitio real, y el analizador
> le da un punto porque la ruta dice "verificacion-clave". Eso es un **falso positivo** y
> se lo voy a reconocer ahora mismo, porque un detector que nunca se equivoca no existe.»

**Diapositiva 4 (opcional, 20 s):** mostrar la salida JSON.

```bash
target/release/phishing-analyzer --json "http://paypa1.com/login/verify"
```

> «También lo puedo usar como herramienta: esto devuelve JSON y se puede alimentar a otro
> sistema, como un antivirus corporativo o un filtro del navegador.»

---

## 4:30 — 5:30 · Lo que el analizador no puede hacer

**Diapositiva 5.**

> «Tres límites, y los digo antes de que me los pregunten:»

1. «Falsos positivos: un sitio legítimo con palabras de gancho en la ruta suma puntos.»
2. «Falsos negativos: un phishing con dominio nuevo y limpio puede salir en verde.»
3. «No mira la página, solo la dirección. Un sitio de phishing dentro de `facebook.com`
   real no lo detecta.»

> «Por eso la conclusión correcta no es "esto es phishing", sino "esto **merece revisión
> humana"». Esa es también la conclusión de la primera diapositiva del manual de
> seguridad: la herramienta ayuda, la persona decide.»

---

**Continúa en el repositorio `honeypot-casero`** con la trampa y el registro de la sesión.
