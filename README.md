# Analizador de phishing

[![CI](https://github.com/runer0101/analizador-phishing/actions/workflows/ci.yml/badge.svg)](https://github.com/runer0101/analizador-phishing/actions/workflows/ci.yml)
[![Demo en vivo](https://img.shields.io/badge/demo%20en%20vivo-1f4fd8?style=flat-square)](https://runer0101.github.io/analizador-phishing/)
[![Licencia](https://img.shields.io/badge/licencia-MIT-1e7a45?style=flat-square)](LICENSE)

Herramienta propia de la actividad de ciberseguridad del 5 de diciembre: **lee un enlace
como texto** y devuelve un veredicto de riesgo con el motivo de cada señal. **Nunca visita
la URL**: no pide DNS, no abre conexiones, no sale a internet.

- Rust, **cero dependencias externas** (solo la biblioteca estándar)
- Once reglas con puntaje, veredicto en tres niveles
- Salida para terminal (con color) y salida JSON para máquinas

> **Demo en vivo:** <https://runer0101.github.io/analizador-phishing/>
> El análisis ocurre en el navegador del visitante, con WebAssembly: el enlace no sale de su equipo.
>
> **Descargas:** [release v0.1.0](https://github.com/runer0101/analizador-phishing/releases/tag/v0.1.0)
> con binarios para Linux, macOS y Windows, y sus sumas SHA-256.

La otra mitad de la actividad es el repositorio hermano
[`honeypot-casero`](../honeypot-casero): una trampa que registra lo que hace un atacante
cuando entra.

## Demo en el navegador

El motor de reglas está compilado a **WebAssembly**: la página analiza el enlace en el
equipo del visitante y **no lo envía a ningún servidor**. No hace falta internet en la
página una vez cargada.

**https://runer0101.github.io/analizador-phishing/**

![Captura de la demo en el navegador](docs/captura-demo.png)

## Descargas

Binarios listos para usar en la [release v0.1.0](https://github.com/runer0101/analizador-phishing/releases/tag/v0.1.0):

| Sistema | Archivo |
| --- | --- |
| Linux x86-64 | `phishing-analyzer-linux-x86_64` |
| Linux ARM64 | `phishing-analyzer-linux-aarch64` |
| macOS Intel | `phishing-analyzer-macos-x86_64` |
| macOS Apple Silicon | `phishing-analyzer-macos-aarch64` |
| Windows x86-64 | `phishing-analyzer-windows-x86_64.exe` |

Cada descarga trae su suma SHA-256 en `phishing-analyzer-SHA256SUMS.txt`.

## Requisitos

Rust 1.74 o superior. Nada más: sin Python, sin Docker, sin red.

```bash
cargo build --release
```

El binario queda en `target/release/phishing-analyzer` y funciona sin internet.

## Uso

```bash
# Los cinco casos de la demostración, con su tabla resumen
target/release/phishing-analyzer --demo

# Un enlace suelto
target/release/phishing-analyzer "http://paypa1.com/login/verify"

# Una lista de enlaces (uno por línea; «#» inicia comentario)
target/release/phishing-analyzer --file enlaces.txt

# Salida JSON para integrarlo con otro sistema
target/release/phishing-analyzer --json "https://www.google.com"

# Sin color (para tuberías o para un proyector con poco contraste)
target/release/phishing-analyzer --no-color "http://paypa1.com/login"
```

## Las once señales

| Código | Puntos | Qué detecta |
| --- | --- | --- |
| `no_https` | 1 | el enlace no usa HTTPS |
| `ip_host` | 2 | una IP en vez de un dominio con nombre |
| `userinfo` | 2 | el `«@»` que esconde el destino real |
| `deep_subdomain` | 1 | cuatro o más etiquetas en el dominio |
| `punycode` | 2 | letras camufladas (`xn--`) |
| `shortener` | 2 | acortadores que esconden el destino |
| `suspicious_tld` | 1 | terminaciones baratas (`.xyz`, `.top`, …) |
| `hyphen_chain` | 1 | dominios con tres o más guiones |
| `hook_words` | 1 | palabras de gancho (`login`, `clave`, `verificar`, …) |
| `brand_impersonation` | 3 | usa el nombre de una marca y no es el sitio oficial |
| `typosquat` | 3 | imita una marca cambiando una letra (`paypa1.com`) |

Marcas vigiladas: PayPal, Google, Facebook, WhatsApp, Microsoft, Banco Unión y BNB. Si el
dominio **es** el oficial o **termina** en `.dominio-oficial`, no se evalúa ninguna marca.

**Niveles:** 5+ puntos → **ALTO** · 3-4 → **MEDIO** · 0-2 → **BAJO**.

## Salida real

```
🔴 ALTO — 5 pts, 3 señales
  http://paypa1.com/login/verify
  dominio: paypa1.com
    +1  no_https    No usa HTTPS: el tráfico puede interceptarse
    +1  hook_words  Palabra de gancho: «login»
    +3  typosquat   Imita a paypal.com (typosquatting)

URL                                               NIVEL  PTS  SEÑALES
--------------------------------------------------------------------------------
http://paypa1.com/login/verify                    ALTO     5  no_https, hook_words, typosquat
http://paypal.secure-verify-login.com/account     ALTO     5  no_https, hook_words, brand_impersonation
http://192.168.56.101/wp-login.php                MEDIO    4  no_https, ip_host, hook_words
https://www.bancounion.com.bo/verificacion-clave  BAJO     1  hook_words
https://www.google.com                            BAJO     0
```

## Límites honestos

- **Falsos positivos**: un sitio legítimo con palabras como `verificacion` en la ruta suma
  un punto. Es el caso de `bancounion.com.bo` en la demostración, y está a la vista.
- **Falsos negativos**: un phishing con dominio nuevo y limpio puede salir `BAJO`.
- **Solo mira la dirección**: no ve la página, así que no detecta un formulario de phishing
  dentro de un dominio real.

La conclusión correcta no es «esto es phishing», sino **«esto merece revisión humana»**.

## Estructura

```
analizador-phishing/
├── src/
│   ├── lib.rs        # motor de reglas, análisis de la URL y veredicto
│   ├── main.rs       # CLI: tabla, JSON, archivos y modo demostración
│   └── wasm.rs       # frontera WebAssembly para la demo del navegador
├── tests/cli.rs      # pruebas de la CLI: códigos de salida y formato
├── site/             # la demo en el navegador (HTML, CSS, JS)
├── .github/workflows/
│   ├── ci.yml        # formato, lints, pruebas y compilación del wasm
│   ├── pages.yml     # publica la demo en GitHub Pages
│   └── release.yml   # binarios de Linux, macOS y Windows en cada tag
├── docs/
│   ├── PRESENTACION.md   # el guion completo de los 12 minutos
│   ├── GUION.md          # la parte del analizador
│   ├── DIAPOSITIVAS.md   # diapositivas 1 a 5
│   ├── ENSAYO.md         # ensayo sin internet y plan B
│   └── captura-demo.png  # captura real de la demo en el navegador
├── scripts/demo.sh   # la demostración del analizador en un comando
└── odd/tasks/        # especificación de la actividad
```

## Verificación

```bash
cargo test                                              # 33 pruebas
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
cargo build --lib --release --target wasm32-unknown-unknown   # el motor de la web
```

## Aviso legal

Material para un laboratorio controlado y **autorizado**. El analizador **no abre ninguna
conexión**: analiza texto que el usuario le entrega. No escanea ni contacta a nadie.
