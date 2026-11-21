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
- **L12** (2026-11-21, Kairos) — El enlace de la demo queda en el **About** del repositorio
  (página del proyecto) y en la descripción, que ahora incluye la URL de la demo; se
  añadieron temas (`rust`, `security`, `phishing`, `wasm`, `static-analysis`,
  `cybersecurity`) para que el repositorio se encuentre por búsqueda.
- **L13** (2026-11-21, Kairos) — El README abre con la demo en vivo y la release, con
  distintivos de CI y licencia. Se añadió el archivo **LICENSE** (MIT), que el `Cargo.toml`
  declaraba pero no existía.
- **L14** (2026-11-21, Kairos) — La URL de la demo también aparece en las diapositivas, en
  el guion, en la guía de ensayo y en el pie de la página, porque es el punto fuerte para
  la exposición: el análisis ocurre en el navegador del visitante.
- **L15** (2026-11-21, señor) — Pide una revisión senior del proyecto: auditoría primero
  (sin tocar nada), después la página web y al final las correcciones de severidad alta y
  media. Pide además que **el código y los comentarios estén en español** y que sean fáciles
  de explicar, porque tiene que presentar el 5 de diciembre.
- **L16** (2026-11-21, Kairos) — Auditoría hecha con evidencia, no a ojo: 1221 entradas
  hostiles y 26 casos límite ejecutados contra el binario, contraste de la página medido en
  el navegador y búsqueda de cualquier referencia de red en el crate.
  - **Alta**: IP en decimal/hexadecimal/octal sin detectar; `http:///dominio` dejaba el host
    vacío; tabuladores y saltos de línea no se borraban como en el navegador; el WebAssembly
    filtraba memoria (el JSON nunca se liberaba).
  - **Media**: barra invertida `\` mal tratada; homoglifos en crudo sin detectar; typosquatting
    limitado a un cambio de dígito; bancos bolivianos sin vigilar; «@» codificado (`%40`) sin
    detectar; contraste de la insignia MEDIO (4.24:1, por debajo de 4.5:1); los guiones de
    `xn--` contaban como guiones del dominio.
- **L17** (2026-11-21, Kairos) — Correcciones aplicadas: el motor ahora imita al navegador al
  leer el enlace (borra tabuladores, trata `\` como barra en http/https e ignora barras de
  más), reconoce las IP en las cuatro notaciones, detecta el «@» codificado, reconoce las
  letras no latinas, distingue el typosquatting con distancia de Damerau-Levenshtein y
  homoglifos, vigila los bancos bolivianos y libera la memoria del WebAssembly.
  Los 11 códigos de señal y los umbrales **no cambian**: solo se corrige y se amplía lo que
  ya estaba anunciado.
- **L18** (2026-11-21, Kairos) — Idioma: identificadores, comentarios, documentación de la
  API, salida JSON y textos de la terminal en español. El JSON ahora usa las claves
  `url`, `dominio`, `nivel`, `puntos` y `senales`.
- **L19** (2026-11-21, Kairos) — Página: nombres de las señales en español, sección de
  limitaciones, lista de marcas vigiladas con los bancos bolivianos, información del binario
  por sistema operativo y cómo ejecutarlo, enlace para saltar al contenido y corrección del
  contraste de la insignia MEDIO.
- **L20** (2026-11-21, Kairos) — Pruebas: de 33 a 59 (48 unitarias y 11 de la terminal),
  con los casos límite de la auditoría. La release publicada v0.1.0 **no se toca**: los
  cambios de código quedan en `main` y la siguiente release será v0.2.0, que publica el
  señor cuando lo ordene.
