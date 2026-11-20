# Actividad: Analizador de phishing — 5 de diciembre

Especificación de la herramienta de la primera mitad de la actividad de ciberseguridad.
La segunda mitad (el honeypot casero) vive en el repositorio hermano `honeypot-casero`.

## Specs

- **S1** — «Dame proyecto de ciberseguridad para poder mostrar en una actividad el 5 de
  diciembre»: la entrega es un proyecto presentable en vivo, no un informe.
- **S2** — «Se puede con el lenguaje rast hace un Analizador de phishing o no»: el
  Analizador de phishing se implementa en Rust.
- **S3** — «No con rast»: el análisis del enlace es **puramente textual**. El programa
  **no visita la URL**: no abre socket, no pide DNS, no usa `requests`.
- **S4** — «que muestre ambos para el 5 el analizador de phishing y honeypot casero que
  hago»: esta actividad muestra **las dos** herramientas; esta es la primera.
- **S7** — Cero dependencias externas (solo `std`): `cargo build --release` produce un
  ejecutable que funciona sin internet y sin instalar nada.
- **S8** — Material de presentación: guion con tiempos, diapositivas y guía de ensayo.
- **S9** — Marco legal y ético: entorno controlado, material visible en español.

## Tasks

| ID | Specs | Tarea | Commit |
| --- | --- | --- | --- |
| T1 | S1, S7 | Crate propio en la raíz del repositorio, `Cargo.toml` autónomo | `chore: bootstrap` |
| T2 | S2, S3 | Motor de reglas + análisis de URL + 25 pruebas unitarias | `feat(analyzer): rule engine with unit tests` |
| T3 | S4, S7 | CLI (tabla, `--json`, `--file`, `--demo`, `--no-color`) + 8 pruebas de CLI | `feat(analyzer): CLI with colored verdicts` |
| T4 | S8 | Guion, diapositivas, guía de ensayo, script de demo y README | `docs: presentation script, slides and rehearsal guide` |
| T5 | S1–S9 | Verificación final: `cargo test`, `clippy`, `fmt`, ensayo sin internet | `chore: final verification` |
| T6 | S10 | Frontera WebAssembly (`src/wasm.rs`), sitio estático y workflow de Pages | `feat(web): browser demo compiled to WebAssembly` |
| T7 | S11 | Workflow de release: binarios por sistema y sumas SHA-256 | `ci: release workflow with per-platform binaries` |
| T8 | S1–S11 | Publicación del repositorio, activación de Pages y primer tag | `chore: publish repository and first release` |

## Contrato técnico

**API de la lib**

```rust
pub enum Level { Low, Medium, High }          // from_score: >=5 alto, 3-4 medio, 0-2 bajo
pub struct Reason { pub code: &'static str, pub points: u32, pub detail: String }
pub struct Report { pub input: String, pub host: String, pub level: Level, pub score: u32, pub reasons: Vec<Reason> }
pub fn analyze(url: &str) -> Report;
pub struct ParsedUrl { pub scheme: String, pub userinfo: Option<String>, pub host: String, pub port: Option<String>, pub path: String, pub query: String }
```

**Reglas** (puntaje → nivel): `no_https` 1 · `ip_host` 2 · `userinfo` 2 · `deep_subdomain` 1 ·
`punycode` 2 · `shortener` 2 · `suspicious_tld` 1 · `hyphen_chain` 1 · `hook_words` 1 ·
`brand_impersonation` 3 · `typosquat` 3.

**CLI**: `--json` · `--file RUTA` · `--demo` · `--no-color` · `-h`. Código de salida 0
(incluso con enlaces sospechosos: el veredicto es información, no un fallo) y 2 solo para
errores de uso. Color únicamente en terminal y nunca con `NO_COLOR` definido.

## Log

- **L1** (2026-11-20, señor) — «Dame proyecto de ciberseguridad para poder mostrar en una
  actividad el 5 de diciembre».
- **L2** (2026-11-20, señor) — «No con rast» / «Se puede con el lenguaje rast hace un
  Analizador de phishing o no»: Rust, y el enlace se analiza como texto.
- **L3** (2026-11-20, señor) — «que muestre ambos para el 5 el analizador de phishing y
  honeypot casero que hago».
- **L4** (2026-11-20, señor) — Decide: **los dos proyectos, en Rust**.
- **L5** (2026-11-20, Kairos) — Cero dependencias externas para que la demo corra sin
  internet; identificadores y comentarios en inglés, material visible en español.
- **L6** (2026-11-20, Kairos) — Repositorio separado con el nombre de la actividad, para
  que cada mitad se pueda revisar, publicar y defender por separado.
- **L7** (2026-11-20, Kairos) — Verificado que el crate **no contiene ninguna referencia de
  red** (`grep` de `std::net`, `TcpStream`, `TcpListener`, `reqwest`: cero resultados).
- **L8** (2026-11-20, señor) — Decide publicar en GitHub **público**, con **Releases** (el
  programa descargable) y **demo en Pages** (la versión web).
- **L9** (2026-11-20, Kairos) — La lib compila a `wasm32-unknown-unknown` **sin añadir
  ninguna dependencia**: el motor de reglas es lógica pura de texto. La frontera con
  JavaScript son cuatro funciones: `wasm_alloc`, `wasm_analyze`, `wasm_last_len` y
  `wasm_dealloc`.
- **L10** (2026-11-20, Kairos) — Dos defectos detectados en la verificación con navegador
  real, antes de publicar: el bloque de resultado se quedaba oculto (atributo `hidden` sin
  quitar) y faltaba el favicon (un 404 en cada carga). Los dos corregidos.
- **L11** (2026-11-20, Kairos) — Los workflows usan **solo acciones de GitHub**
  (`checkout`, `cache`, `configure-pages`, `upload-pages-artifact`, `deploy-pages`), sin
  acciones de terceros: en un repositorio de ciberseguridad conviene que la cadena de
  suministro sea corta y auditada.
