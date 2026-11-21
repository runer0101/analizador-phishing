//! Analizador estático de enlaces de phishing.
//!
//! La idea es sencilla: **el enlace se lee como texto y no se visita**. El programa no
//! abre conexiones, no pide nombres de dominio y no sale a internet. Solo aplica una
//! lista de reglas que reconocen señales típicas de fraude y las convierte en un
//! veredicto: **ALTO**, **MEDIO** o **BAJO**.
//!
//! Cada regla suma puntos. Al final se suman todos:
//!
//! | Puntos | Veredicto |
//! | --- | --- |
//! | 5 o más | **ALTO** |
//! | 3 o 4 | **MEDIO** |
//! | 0 a 2 | **BAJO** |
//!
//! Todo está escrito en español para que se pueda explicar en una presentación.

use std::fmt;

/// La demostración del navegador compila esta biblioteca a WebAssembly; toda la
/// frontera con JavaScript está en `wasm.rs`.
#[cfg(target_arch = "wasm32")]
mod wasm;

/// Nivel de riesgo que devuelve el analizador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nivel {
    Bajo,
    Medio,
    Alto,
}

impl Nivel {
    /// Convierte el total de puntos en un nivel de riesgo.
    pub fn desde_puntos(puntos: u32) -> Self {
        match puntos {
            0..=2 => Nivel::Bajo,
            3..=4 => Nivel::Medio,
            _ => Nivel::Alto,
        }
    }

    /// Texto que se muestra en la terminal (mayúsculas).
    pub fn etiqueta(self) -> &'static str {
        match self {
            Nivel::Bajo => "BAJO",
            Nivel::Medio => "MEDIO",
            Nivel::Alto => "ALTO",
        }
    }

    /// Texto en minúsculas para el JSON.
    pub fn token(self) -> &'static str {
        match self {
            Nivel::Bajo => "bajo",
            Nivel::Medio => "medio",
            Nivel::Alto => "alto",
        }
    }

    /// Código de color ANSI: verde, amarillo o rojo.
    pub fn color(self) -> &'static str {
        match self {
            Nivel::Bajo => "\x1b[32m",
            Nivel::Medio => "\x1b[33m",
            Nivel::Alto => "\x1b[31m",
        }
    }
}

impl fmt::Display for Nivel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.etiqueta())
    }
}

/// Una señal detectada: su código, cuántos puntos aporta y por qué se detectó.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Senal {
    pub codigo: &'static str,
    pub puntos: u32,
    pub detalle: String,
}

/// El resultado de analizar un enlace.
#[derive(Debug, Clone)]
pub struct Informe {
    /// El enlace tal como lo escribió la persona.
    pub url: String,
    /// El dominio normalizado (minúsculas, sin `www.` ni punto final).
    pub dominio: String,
    pub nivel: Nivel,
    pub puntos: u32,
    pub senales: Vec<Senal>,
}

impl Informe {
    /// Una línea corta: nivel, puntos y cuántas señales se encontraron.
    pub fn resumen(&self) -> String {
        let plural = if self.senales.len() == 1 { "" } else { "es" };
        let puntos = if self.puntos == 1 { "punto" } else { "puntos" };
        format!(
            "{} ({} {}, {} señal{})",
            self.nivel.etiqueta(),
            self.puntos,
            puntos,
            self.senales.len(),
            plural
        )
    }

    /// Convierte el informe en JSON. Se hace a mano para no usar ninguna biblioteca.
    pub fn a_json(&self) -> String {
        let senales: Vec<String> = self
            .senales
            .iter()
            .map(|senal| {
                format!(
                    "{{\"codigo\":{},\"puntos\":{},\"detalle\":{}}}",
                    cadena_json(senal.codigo),
                    senal.puntos,
                    cadena_json(&senal.detalle)
                )
            })
            .collect();
        format!(
            "{{\"url\":{},\"dominio\":{},\"nivel\":{},\"puntos\":{},\"senales\":[{}]}}",
            cadena_json(&self.url),
            cadena_json(&self.dominio),
            cadena_json(self.nivel.token()),
            self.puntos,
            senales.join(",")
        )
    }
}

/// Convierte un texto en un literal de JSON válido (con comillas).
pub fn cadena_json(valor: &str) -> String {
    let mut salida = String::with_capacity(valor.len() + 2);
    salida.push('"');
    for caracter in valor.chars() {
        match caracter {
            '"' => salida.push_str("\\\""),
            '\\' => salida.push_str("\\\\"),
            '\n' => salida.push_str("\\n"),
            '\r' => salida.push_str("\\r"),
            '\t' => salida.push_str("\\t"),
            c if (c as u32) < 0x20 => salida.push_str(&format!("\\u{:04x}", c as u32)),
            c => salida.push(c),
        }
    }
    salida.push('"');
    salida
}

/// Marcas conocidas y su sitio web oficial.
pub const MARCAS: &[(&str, &str)] = &[
    ("paypal", "paypal.com"),
    ("google", "google.com"),
    ("facebook", "facebook.com"),
    ("whatsapp", "whatsapp.com"),
    ("microsoft", "microsoft.com"),
    ("amazon", "amazon.com"),
    ("apple", "apple.com"),
    // Bancos de Bolivia
    ("bcp", "bcp.com.bo"),
    ("bnb", "bnb.com.bo"),
    ("bancounion", "bancounion.com.bo"),
    ("mercantilsantacruz", "mercantilsantacruz.com.bo"),
    ("bancoestado", "bancoestado.com.bo"),
];

/// Servicios que acortan el enlace y esconden el destino real.
pub const ACORTADORES: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
];

/// Terminaciones baratas, muy usadas por los estafadores.
pub const TERMINACIONES_SOSPECHOSAS: &[&str] = &[
    ".xyz", ".top", ".tk", ".click", ".zip", ".icu", ".buzz", ".link", ".work", ".rest",
];

/// Palabras de gancho: sirven para que la persona haga clic sin pensar.
pub const PALABRAS_GANCHO: &[&str] = &[
    "login",
    "signin",
    "sign-in",
    "verify",
    "verificar",
    "verification",
    "secure",
    "seguridad",
    "update",
    "actualizar",
    "confirm",
    "confirmar",
    "banco",
    "bancario",
    "clave",
    "password",
    "contrasena",
    "contraseña",
    "cuenta",
    "acceso",
    "recovery",
    "recuperar",
    "bloqueo",
    "suspendido",
    "suspended",
    "unusual",
    "urgente",
    "inmediato",
    "premio",
    "ganador",
];

/// El enlace, desarmado en partes.
///
/// No se usa ninguna biblioteca de URLs: el desarmado se hace a mano para que el
/// programa no dependa de nada externo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlAnalizada {
    pub esquema: String,
    /// Texto antes del «@», si lo hay (es la parte que engaña a la persona).
    pub usuario: Option<String>,
    pub dominio: String,
    pub puerto: Option<String>,
    pub ruta: String,
    pub consulta: String,
}

impl UrlAnalizada {
    /// Desarma el enlace en sus partes.
    ///
    /// Se imitan tres manías de los navegadores, porque si no el analizador vería un
    /// dominio distinto al que realmente abriría el navegador:
    ///
    /// 1. Se borran los tabuladores y saltos de línea (el navegador los elimina).
    /// 2. Las barras invertidas `\` cuentan como barras en `http` y `https`.
    /// 3. Las barras de más después de `://` se ignoran (`http:///sitio` es `sitio`).
    pub fn parsear(entrada: &str) -> UrlAnalizada {
        let limpio: String = entrada
            .trim()
            .chars()
            .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
            .collect();

        let (esquema, resto_original) = match limpio.find("://") {
            Some(posicion) => (
                limpio[..posicion].to_ascii_lowercase(),
                limpio[posicion + 3..].to_string(),
            ),
            None => ("http".to_string(), limpio.clone()),
        };

        // Solo en http y https la barra invertida se comporta como una barra normal,
        // y las barras de más se ignoran: http:///sitio es el sitio "sitio".
        let especial = esquema == "http" || esquema == "https";
        let mut resto = if especial {
            resto_original.replace('\\', "/")
        } else {
            resto_original
        };
        if especial {
            resto = resto.trim_start_matches('/').to_string();
        }
        let resto = resto.as_str();

        let fin_de_autoridad = resto.find(['/', '?', '#']).unwrap_or(resto.len());
        let autoridad = &resto[..fin_de_autoridad];
        let cola = &resto[fin_de_autoridad..];

        // El «@» puede venir escrito tal cual o codificado como %40.
        let minusculas = autoridad.to_ascii_lowercase();
        let posicion_arroba = minusculas.rfind('@');
        let posicion_codificado = minusculas.rfind("%40");
        let corte = match (posicion_arroba, posicion_codificado) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        let (usuario, parte_dominio) = match corte {
            Some(posicion) => {
                let despues = if minusculas[posicion..].starts_with("%40") {
                    posicion + 3
                } else {
                    posicion + 1
                };
                (
                    Some(autoridad[..posicion].to_string()),
                    &autoridad[despues..],
                )
            }
            None => (None, autoridad),
        };

        let (dominio_crudo, puerto) = separar_dominio_y_puerto(parte_dominio);
        let dominio = normalizar_dominio(&dominio_crudo);

        let sin_fragmento = cola.split('#').next().unwrap_or("");
        let (ruta, consulta) = match sin_fragmento.split_once('?') {
            Some((r, c)) => (r.to_string(), c.to_string()),
            None => (sin_fragmento.to_string(), String::new()),
        };

        UrlAnalizada {
            esquema,
            usuario,
            dominio,
            puerto,
            ruta,
            consulta,
        }
    }
}

/// Separa el dominio del puerto, teniendo en cuenta las IP entre corchetes.
fn separar_dominio_y_puerto(parte: &str) -> (String, Option<String>) {
    if let Some(resto) = parte.strip_prefix('[') {
        // Dirección IPv6 entre corchetes: [::1]:2222
        return match resto.split_once(']') {
            Some((dominio, despues)) => {
                let puerto = despues.strip_prefix(':').map(|p| p.to_string());
                (format!("[{}]", dominio), puerto)
            }
            None => (parte.to_string(), None),
        };
    }
    match parte.split_once(':') {
        Some((dominio, puerto)) => (dominio.to_string(), Some(puerto.to_string())),
        None => (parte.to_string(), None),
    }
}

/// Deja el dominio como lo vería una persona: minúsculas, sin punto final y sin `www.`.
pub fn normalizar_dominio(dominio: &str) -> String {
    let mut valor = dominio.trim().to_ascii_lowercase();
    while valor.ends_with('.') {
        valor.pop();
    }
    if let Some(resto) = valor.strip_prefix("www.") {
        valor = resto.to_string();
    }
    valor
}

/// Analiza un enlace y devuelve su veredicto.
pub fn analizar(entrada: &str) -> Informe {
    let url = UrlAnalizada::parsear(entrada);
    let dominio = url.dominio.clone();
    let dominio_minusculas = dominio.to_ascii_lowercase();
    let texto_minusculas =
        format!("{} {} {}", url.dominio, url.ruta, url.consulta).to_ascii_lowercase();
    let es_ip = es_direccion_ip(&dominio);

    let mut senales: Vec<Senal> = Vec::new();

    // 1. Sin HTTPS el tráfico se puede interceptar por el camino.
    if url.esquema != "https" {
        senales.push(Senal {
            codigo: "sin_https",
            puntos: 1,
            detalle: "No usa HTTPS: el tráfico puede interceptarse".to_string(),
        });
    }

    // 2. Una IP cruda en lugar de un dominio con nombre.
    if es_ip {
        senales.push(Senal {
            codigo: "ip_dominio",
            puntos: 2,
            detalle: "Usa una dirección IP en vez de un dominio con nombre".to_string(),
        });
    }

    // 3. El «@» esconde el dominio real detrás de uno falso.
    if url.usuario.is_some() {
        senales.push(Senal {
            codigo: "usuario_oculto",
            puntos: 2,
            detalle: "Contiene «@»: el dominio real queda escondido detrás".to_string(),
        });
    }

    // 4. Muchos subdominios: el dominio de verdad está al final de la cadena.
    if !es_ip && cantidad_etiquetas(&dominio_minusculas) >= 4 {
        senales.push(Senal {
            codigo: "subdominios",
            puntos: 1,
            detalle: "Demasiados subdominios: el dominio real está al final".to_string(),
        });
    }

    // 5. Letras camufladas: tanto la forma codificada (xn--) como el Unicode crudo.
    if dominio_minusculas.contains("xn--") {
        senales.push(Senal {
            codigo: "letras_camufladas",
            puntos: 2,
            detalle: "Punycode: el dominio usa letras codificadas".to_string(),
        });
    } else if !dominio.is_ascii() {
        senales.push(Senal {
            codigo: "letras_camufladas",
            puntos: 2,
            detalle: "Contiene letras no latinas: pueden imitar a las letras verdaderas"
                .to_string(),
        });
    }

    // 6. Acortadores: esconden a dónde lleva el enlace de verdad.
    if es_acortador(&dominio_minusculas) {
        senales.push(Senal {
            codigo: "acortador",
            puntos: 2,
            detalle: "Link acortado: el destino real está oculto".to_string(),
        });
    }

    // 7. Terminaciones baratas.
    if tiene_terminacion_sospechosa(&dominio_minusculas) {
        senales.push(Senal {
            codigo: "terminacion_rara",
            puntos: 1,
            detalle: "Terminación poco confiable".to_string(),
        });
    }

    // 8. Muchos guiones: patrón clásico de suplantación.
    if !es_ip && cantidad_guiones(&dominio_minusculas) >= 3 {
        senales.push(Senal {
            codigo: "guiones",
            puntos: 1,
            detalle: "Muchos guiones en el dominio: patrón habitual de suplantación".to_string(),
        });
    }

    // 9. Palabras de gancho en el dominio, la ruta o la consulta.
    if let Some(palabra) = primera_palabra_gancho(&texto_minusculas) {
        senales.push(Senal {
            codigo: "palabra_gancho",
            puntos: 1,
            detalle: format!("Palabra de gancho: «{palabra}»"),
        });
    }

    // 10 y 11. Marcas imitadas y typosquatting.
    for (nombre, oficial) in MARCAS {
        if dominio_minusculas == *oficial || dominio_minusculas.ends_with(&format!(".{oficial}")) {
            break; // Es el sitio oficial: no se evalúa ninguna marca.
        }
        if usa_nombre_de_marca(&dominio_minusculas, nombre) {
            senales.push(Senal {
                codigo: "marca_falsa",
                puntos: 3,
                detalle: format!(
                    "Usa el nombre de {nombre} pero no es el sitio oficial ({oficial})"
                ),
            });
            break;
        }
        if imita_una_marca(&dominio_minusculas, nombre) {
            senales.push(Senal {
                codigo: "typosquatting",
                puntos: 3,
                detalle: format!("Imita a {oficial} con una diferencia mínima"),
            });
            break;
        }
    }

    let puntos: u32 = senales.iter().map(|senal| senal.puntos).sum();
    let nivel = Nivel::desde_puntos(puntos);

    Informe {
        url: entrada.trim().to_string(),
        dominio,
        nivel,
        puntos,
        senales,
    }
}

/// ¿El host es una dirección IP?
///
/// Cubre las cuatro notaciones que aceptan los navegadores: IPv4 con puntos (`1.2.3.4`),
/// IPv6 (`::1`), decimal (`2130706433`), hexadecimal (`0x7f000001`) y octal (`017700000001`).
pub fn es_direccion_ip(dominio: &str) -> bool {
    let limpio = dominio.trim_start_matches('[').trim_end_matches(']');
    if limpio.contains(':') {
        return true; // IPv6
    }

    // IPv4 con puntos: cuatro números entre 0 y 255.
    let partes: Vec<&str> = limpio.split('.').collect();
    if partes.len() == 4
        && partes
            .iter()
            .all(|parte| !parte.is_empty() && parte.parse::<u8>().is_ok())
    {
        return true;
    }

    // Notaciones de un solo número: decimal, hexadecimal u octal.
    if limpio.is_empty() || !limpio.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if let Some(resto) = limpio
        .strip_prefix("0x")
        .or_else(|| limpio.strip_prefix("0X"))
    {
        return !resto.is_empty() && resto.chars().all(|c| c.is_ascii_hexdigit());
    }
    if limpio.len() > 1 && limpio.starts_with('0') {
        return limpio[1..].chars().all(|c| ('0'..='7').contains(&c));
    }
    limpio.chars().all(|c| c.is_ascii_digit())
}

/// Cuántas etiquetas tiene el dominio (`a.b.c.d` son cuatro).
pub fn cantidad_etiquetas(dominio: &str) -> usize {
    dominio.split('.').filter(|parte| !parte.is_empty()).count()
}

/// Cuántos guiones tiene el dominio, sin contar los de `xn--` (que son del código).
pub fn cantidad_guiones(dominio: &str) -> usize {
    dominio
        .split('.')
        .filter(|etiqueta| !etiqueta.starts_with("xn--"))
        .map(|etiqueta| etiqueta.matches('-').count())
        .sum()
}

/// ¿El dominio es (o termina siendo) un acortador conocido?
pub fn es_acortador(dominio: &str) -> bool {
    ACORTADORES.contains(&dominio)
}

/// ¿El dominio termina en una terminación poco confiable?
pub fn tiene_terminacion_sospechosa(dominio: &str) -> bool {
    TERMINACIONES_SOSPECHOSAS
        .iter()
        .any(|terminacion| dominio.ends_with(terminacion))
}

/// Primera palabra de gancho encontrada (el texto llega en minúsculas).
pub fn primera_palabra_gancho(texto: &str) -> Option<&'static str> {
    PALABRAS_GANCHO
        .iter()
        .find(|palabra| texto.contains(*palabra))
        .copied()
}

/// La «clave» de una etiqueta: sin guiones y en minúsculas.
///
/// Sirve para comparar nombres: `banco-union` y `bancounion` son la misma clave.
fn clave_de_marca(etiqueta: &str) -> String {
    etiqueta.replace('-', "").to_ascii_lowercase()
}

/// ¿El dominio usa el nombre de una marca en alguna de sus etiquetas?
pub fn usa_nombre_de_marca(dominio: &str, nombre: &str) -> bool {
    let marca = clave_de_marca(nombre);
    dominio.split('.').any(|etiqueta| {
        let clave = clave_de_marca(etiqueta);
        clave == marca || (clave.len() > marca.len() && clave.contains(&marca))
    })
}

/// Normaliza los homoglifos más comunes: letras que se parecen a otras.
///
/// `rn` se lee como `m`, `vv` como `w`, y los dígitos `0 1 3 4 5 7` imitan a
/// `o l e a s t`.
pub fn normalizar_homoglifos(texto: &str) -> String {
    let mut salida = String::with_capacity(texto.len());
    let caracteres: Vec<char> = texto.chars().collect();
    let mut indice = 0;
    while indice < caracteres.len() {
        let actual = caracteres[indice];
        let siguiente = caracteres.get(indice + 1).copied();
        match (actual, siguiente) {
            ('r', Some('n')) => {
                salida.push('m');
                indice += 2;
                continue;
            }
            ('v', Some('v')) => {
                salida.push('w');
                indice += 2;
                continue;
            }
            _ => {}
        }
        salida.push(match actual {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            otro => otro,
        });
        indice += 1;
    }
    salida
}

/// Distancia entre dos textos: cuántos cambios hay que hacer para pasar de uno a otro.
///
/// Es la distancia de Damerau-Levenshtein: cuenta como un solo cambio el intercambio
/// de dos letras vecinas (`paypla` → `paypal`), que con la distancia simple serían dos.
pub fn distancia_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    let mut anterior_anterior: Vec<usize> = vec![0; b.len() + 1];
    let mut anterior: Vec<usize> = (0..=b.len()).collect();
    let mut actual: Vec<usize> = vec![0; b.len() + 1];

    for (i, &caracter_a) in a.iter().enumerate() {
        actual[0] = i + 1;
        for (j, &caracter_b) in b.iter().enumerate() {
            let costo = usize::from(caracter_a != caracter_b);
            let mut valor = (actual[j] + 1)
                .min(anterior[j + 1] + 1)
                .min(anterior[j] + costo);
            // Intercambio de dos letras vecinas: cuenta como un solo cambio.
            if i > 0 && j > 0 && caracter_a == b[j - 1] && a[i - 1] == caracter_b {
                valor = valor.min(anterior_anterior[j - 1] + 1);
            }
            actual[j + 1] = valor;
        }
        anterior_anterior = anterior;
        anterior = actual.clone();
    }

    anterior[b.len()]
}

/// ¿El dominio imita a una marca con una diferencia mínima?
///
/// Se comparan la primera etiqueta del dominio con el nombre de la marca, después de
/// normalizar los homoglifos. Si la diferencia es de un solo cambio (o none), es un
/// typosquatting.
pub fn imita_una_marca(dominio: &str, nombre: &str) -> bool {
    let Some(primera) = dominio.split('.').next() else {
        return false;
    };
    if primera.is_empty() {
        return false;
    }
    let normalizado = normalizar_homoglifos(&clave_de_marca(primera));
    let marca = normalizar_homoglifos(&clave_de_marca(nombre));
    if normalizado.is_empty() || marca.is_empty() {
        return false;
    }
    // Una diferencia mínima: o es la misma marca con una letra cambiada, de más o de menos.
    distancia_levenshtein(&normalizado, &marca) <= 1
}

/// Un enlace de la demostración con su veredicto esperado y la nota que se explica.
pub struct CasoDemo {
    pub url: &'static str,
    pub esperado: Nivel,
    pub nota: &'static str,
}

/// Los cinco enlaces de la demostración.
pub const CASOS_DEMO: &[CasoDemo] = &[
    CasoDemo {
        url: "http://paypa1.com/login/verify",
        esperado: Nivel::Alto,
        nota: "El «1» imita la «l» de PayPal: typosquatting.",
    },
    CasoDemo {
        url: "http://paypal.secure-verify-login.com/account",
        esperado: Nivel::Alto,
        nota: "Usa el nombre de PayPal pero el dominio real termina en .com.",
    },
    CasoDemo {
        url: "http://192.168.56.101/wp-login.php",
        esperado: Nivel::Medio,
        nota: "Login de WordPress servido desde una IP cruda.",
    },
    CasoDemo {
        url: "https://www.bancounion.com.bo/verificacion-clave",
        esperado: Nivel::Bajo,
        nota: "Sitio real: el analizador lo marca por las palabras de la ruta (falso positivo).",
    },
    CasoDemo {
        url: "https://www.google.com",
        esperado: Nivel::Bajo,
        nota: "Sitio legítimo: ninguna señal sospechosa.",
    },
];

#[cfg(test)]
mod pruebas {
    use super::*;

    fn codigos(informe: &Informe) -> Vec<&str> {
        informe.senales.iter().map(|senal| senal.codigo).collect()
    }

    fn puntos_de(informe: &Informe, codigo: &str) -> u32 {
        informe
            .senales
            .iter()
            .find(|senal| senal.codigo == codigo)
            .unwrap_or_else(|| panic!("falta la señal {codigo}"))
            .puntos
    }

    // ---------------------------------------------------------------- reglas

    #[test]
    fn detecta_que_no_usa_https() {
        let informe = analizar("http://ejemplo.com");
        assert_eq!(informe.senales[0].codigo, "sin_https");
        assert_eq!(informe.senales[0].puntos, 1);
    }

    #[test]
    fn con_https_no_aparece_la_senal_de_https() {
        let informe = analizar("https://ejemplo.com");
        assert!(!codigos(&informe).contains(&"sin_https"));
    }

    #[test]
    fn detecta_ip_con_puntos() {
        let informe = analizar("https://192.168.1.10/login");
        assert!(codigos(&informe).contains(&"ip_dominio"));
        assert_eq!(puntos_de(&informe, "ip_dominio"), 2);
    }

    #[test]
    fn detecta_ip_en_decimal() {
        let informe = analizar("https://2130706433/login");
        assert!(codigos(&informe).contains(&"ip_dominio"));
    }

    #[test]
    fn detecta_ip_en_hexadecimal() {
        let informe = analizar("https://0x7f000001/login");
        assert!(codigos(&informe).contains(&"ip_dominio"));
    }

    #[test]
    fn detecta_ip_en_octal() {
        let informe = analizar("https://017700000001/login");
        assert!(codigos(&informe).contains(&"ip_dominio"));
    }

    #[test]
    fn detecta_ip_en_ipv6() {
        let informe = analizar("https://[::1]/login");
        assert!(codigos(&informe).contains(&"ip_dominio"));
    }

    #[test]
    fn una_ip_no_cuenta_como_subdominios() {
        let informe = analizar("https://192.168.1.10/");
        assert!(!codigos(&informe).contains(&"subdominios"));
    }

    #[test]
    fn detecta_el_arroba_que_esconde_el_destino() {
        let informe = analizar("http://banco.com@banco-falso.com/");
        assert!(codigos(&informe).contains(&"usuario_oculto"));
        assert_eq!(puntos_de(&informe, "usuario_oculto"), 2);
    }

    #[test]
    fn detecta_el_arroba_codificado() {
        let informe = analizar("http://banco.com%40banco-falso.com/");
        assert!(codigos(&informe).contains(&"usuario_oculto"));
        assert_eq!(informe.dominio, "banco-falso.com");
    }

    #[test]
    fn el_arroba_no_esconde_el_dominio_real() {
        let url = UrlAnalizada::parsear("http://banco.com@banco-falso.com/x");
        assert_eq!(url.usuario.as_deref(), Some("banco.com"));
        assert_eq!(url.dominio, "banco-falso.com");
    }

    #[test]
    fn detecta_demasiados_subdominios() {
        let informe = analizar("https://login.banco.com.seguro.servidor.com/");
        assert!(codigos(&informe).contains(&"subdominios"));
    }

    #[test]
    fn detecta_punycode() {
        let informe = analizar("https://xn--80ak6aa92e.com/");
        assert!(codigos(&informe).contains(&"letras_camufladas"));
    }

    #[test]
    fn detecta_letras_no_latinas() {
        let informe = analizar("https://p\u{0430}ypal.com/");
        assert!(codigos(&informe).contains(&"letras_camufladas"));
    }

    #[test]
    fn detecta_acortador() {
        let informe = analizar("http://bit.ly/3xAbCdE");
        assert!(codigos(&informe).contains(&"acortador"));
        assert_eq!(puntos_de(&informe, "acortador"), 2);
    }

    #[test]
    fn detecta_terminacion_rara() {
        let informe = analizar("https://banco-verificacion.xyz/");
        assert!(codigos(&informe).contains(&"terminacion_rara"));
    }

    #[test]
    fn detecta_muchos_guiones() {
        let informe = analizar("https://banco-seguro-verificacion-cuenta.com/");
        assert!(codigos(&informe).contains(&"guiones"));
    }

    #[test]
    fn los_guiones_del_punycode_no_cuentan() {
        let informe = analizar("https://xn--pypal-4ve.com/");
        assert!(!codigos(&informe).contains(&"guiones"));
    }

    #[test]
    fn detecta_palabra_de_gancho() {
        let informe = analizar("https://sitio-real.com/login");
        assert!(codigos(&informe).contains(&"palabra_gancho"));
    }

    #[test]
    fn detecta_marca_falsa() {
        let informe = analizar("http://paypal.secure-verify-login.com/account");
        assert!(codigos(&informe).contains(&"marca_falsa"));
        assert_eq!(puntos_de(&informe, "marca_falsa"), 3);
    }

    #[test]
    fn la_marca_dentro_de_una_etiqueta_larga_tambien_cuenta() {
        let informe = analizar("https://secure-paypal-verificacion.com/");
        assert!(codigos(&informe).contains(&"marca_falsa"));
    }

    #[test]
    fn detecta_typosquatting_con_digito() {
        let informe = analizar("http://paypa1.com/login/verify");
        assert!(codigos(&informe).contains(&"typosquatting"));
        assert_eq!(puntos_de(&informe, "typosquatting"), 3);
    }

    #[test]
    fn detecta_typosquatting_con_letra_de_mas() {
        let informe = analizar("http://paypail.com/");
        assert!(codigos(&informe).contains(&"typosquatting"));
    }

    #[test]
    fn detecta_typosquatting_con_letra_de_menos() {
        let informe = analizar("http://paypl.com/");
        assert!(codigos(&informe).contains(&"typosquatting"));
    }

    #[test]
    fn detecta_typosquatting_con_letras_intercambiadas() {
        let informe = analizar("http://paypla.com/");
        assert!(codigos(&informe).contains(&"typosquatting"));
    }

    #[test]
    fn detecta_typosquatting_con_homoglofos() {
        let informe = analizar("http://vvhatsapp.com/");
        assert!(codigos(&informe).contains(&"typosquatting"));
    }

    #[test]
    fn la_marca_oficial_no_da_problemas() {
        let informe = analizar("https://www.paypal.com/");
        assert!(!codigos(&informe).contains(&"marca_falsa"));
        assert!(!codigos(&informe).contains(&"typosquatting"));
    }

    #[test]
    fn la_marca_dentro_de_un_sitio_oficial_no_da_problemas() {
        let informe = analizar("https://www.bancounion.com.bo/");
        assert!(!codigos(&informe).contains(&"marca_falsa"));
        assert!(!codigos(&informe).contains(&"typosquatting"));
    }

    #[test]
    fn los_bancos_bolivianos_estan_vigilados() {
        for (nombre, _) in [("bcp.com.bo", "bcp"), ("bnb.com.bo", "bnb")] {
            let informe = analizar(&format!("https://{nombre}/"));
            assert!(
                !codigos(&informe).contains(&"marca_falsa"),
                "{nombre} no debería dar señal de marca falsa"
            );
        }
        let informe = analizar("https://bcp-secure-verificacion.com.bo/");
        assert!(codigos(&informe).contains(&"marca_falsa"));
    }

    // ------------------------------------------------------------- umbrales

    #[test]
    fn los_umbrales_son_5_mas_alto_y_3_a_4_medio() {
        assert_eq!(Nivel::desde_puntos(0), Nivel::Bajo);
        assert_eq!(Nivel::desde_puntos(2), Nivel::Bajo);
        assert_eq!(Nivel::desde_puntos(3), Nivel::Medio);
        assert_eq!(Nivel::desde_puntos(4), Nivel::Medio);
        assert_eq!(Nivel::desde_puntos(5), Nivel::Alto);
        assert_eq!(Nivel::desde_puntos(9), Nivel::Alto);
    }

    #[test]
    fn el_puntaje_es_la_suma_de_las_senales() {
        let informe = analizar("http://paypa1.com/login/verify");
        let suma: u32 = informe.senales.iter().map(|senal| senal.puntos).sum();
        assert_eq!(informe.puntos, suma);
        assert_eq!(informe.nivel, Nivel::Alto);
    }

    // ------------------------------------------------------------- robustez

    #[test]
    fn una_entrada_vacia_no_entra_en_panico() {
        let informe = analizar("");
        assert_eq!(informe.nivel, Nivel::Bajo);
        assert_eq!(informe.dominio, "");
    }

    #[test]
    fn un_enlace_sin_dominio_no_entra_en_panico() {
        for entrada in ["http://", "https://", "http://:80", "http://@", "http://@@"] {
            let informe = analizar(entrada);
            assert!(informe.dominio.is_empty(), "entrada: {entrada}");
            assert!(informe.puntos <= 30, "entrada: {entrada}");
        }
    }

    #[test]
    fn una_entrada_muy_larga_no_entra_en_panico() {
        let entrada = format!("http://{}.com/login", "a".repeat(50_000));
        let informe = analizar(&entrada);
        assert!(!informe.dominio.is_empty());
    }

    #[test]
    fn caracteres_raros_no_entran_en_panico() {
        for entrada in [
            "http://exa mple.com/",
            "http://[",
            "http://[::1",
            "http://%",
            "http://%zz",
            "http://xn--",
            "ht!tp://x",
            "://",
            "http://a..b",
            "http://..",
            "http://.",
        ] {
            let informe = analizar(entrada);
            assert!(informe.puntos <= 30, "entrada: {entrada}");
        }
    }

    #[test]
    fn un_solo_esquema_se_trata_como_http() {
        let url = UrlAnalizada::parsear("ejemplo.com/hola");
        assert_eq!(url.esquema, "http");
        assert_eq!(url.dominio, "ejemplo.com");
        assert_eq!(url.ruta, "/hola");
    }

    #[test]
    fn las_mayusculas_no_engañan_al_analizador() {
        let url = UrlAnalizada::parsear("HTTPS://WWW.Ejemplo.COM/LOGIN");
        assert_eq!(url.esquema, "https");
        assert_eq!(url.dominio, "ejemplo.com");
        assert_eq!(url.ruta, "/LOGIN");
    }

    #[test]
    fn el_puerto_no_forma_parte_del_dominio() {
        let url = UrlAnalizada::parsear("http://paypa1.com:8080/login");
        assert_eq!(url.dominio, "paypa1.com");
        assert_eq!(url.puerto.as_deref(), Some("8080"));
    }

    #[test]
    fn el_punto_final_del_dominio_se_quita() {
        let url = UrlAnalizada::parsear("http://paypa1.com./login");
        assert_eq!(url.dominio, "paypa1.com");
    }

    #[test]
    fn las_barras_de_mas_no_esconden_el_dominio() {
        let url = UrlAnalizada::parsear("http:///paypa1.com/login");
        assert_eq!(url.dominio, "paypa1.com");
        let informe = analizar("http:///paypa1.com/login");
        assert_eq!(informe.nivel, Nivel::Alto);
    }

    #[test]
    fn los_tabuladores_se_borran_como_en_el_navegador() {
        let url = UrlAnalizada::parsear("http://exa\tmple.com/");
        assert_eq!(url.dominio, "example.com");
    }

    #[test]
    fn la_barra_invertida_ends_la_autoridad_como_en_el_navegador() {
        let url = UrlAnalizada::parsear("http://evil.com\\@paypa1.com/");
        assert_eq!(url.dominio, "evil.com");
    }

    #[test]
    fn las_terminaciones_dobles_no_se_confunden() {
        let url = UrlAnalizada::parsear("https://www.bancounion.com.bo/");
        assert_eq!(url.dominio, "bancounion.com.bo");
        assert_eq!(cantidad_etiquetas(&url.dominio), 3);
    }

    // ------------------------------------------------------------ auxiliares

    #[test]
    fn la_distancia_de_levenshtein_cuenta_las_letras() {
        assert_eq!(distancia_levenshtein("paypal", "paypal"), 0);
        assert_eq!(distancia_levenshtein("paypal", "paypa1"), 1);
        assert_eq!(distancia_levenshtein("paypal", "paypai"), 1);
        assert_eq!(distancia_levenshtein("paypal", "paypl"), 1);
        assert_eq!(distancia_levenshtein("paypal", "paypla"), 1);
        assert_eq!(distancia_levenshtein("paypal", "otro"), 6);
    }

    #[test]
    fn los_homoglifos_se_normalizan() {
        assert_eq!(normalizar_homoglifos("rnicrosoft"), "microsoft");
        assert_eq!(normalizar_homoglifos("vvhatsapp"), "whatsapp");
        assert_eq!(normalizar_homoglifos("micros0ft"), "microsoft");
    }

    #[test]
    fn el_json_escapa_las_comillas() {
        assert_eq!(cadena_json("a\"b\\c\nd"), r#""a\"b\\c\nd""#);
    }

    #[test]
    fn el_json_del_informe_tiene_la_forma_esperada() {
        let json = analizar("http://paypa1.com/login/verify").a_json();
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"nivel\":\"alto\""));
        assert!(json.contains("\"codigo\":\"typosquatting\""));
    }

    #[test]
    fn los_casos_de_la_demo_cumplen_lo_prometido() {
        for caso in CASOS_DEMO {
            let informe = analizar(caso.url);
            assert_eq!(
                informe.nivel, caso.esperado,
                "veredicto inesperado para {}: {:?}",
                caso.url, informe.senales
            );
        }
    }
}
