//! Línea de órdenes del analizador de phishing.

use phishing_analyzer::{analizar, Informe, Nivel, CASOS_DEMO};
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const AYUDA: &str = "\
phishing-analyzer — analiza enlaces de phishing como texto, sin visitarlos

Uso:
  phishing-analyzer [OPCIONES] [URL]...

Opciones:
  --json        Imprime un arreglo JSON con un objeto por enlace
  --file RUTA   Lee los enlaces de un archivo (uno por línea; «#» inicia comentario)
  --demo        Analiza los casos de la demostración
  --no-color    Desactiva el color ANSI
  -h, --help    Muestra esta ayuda

El veredicto es información, no un fallo: el código de salida es 0 aunque se detecten
enlaces sospechosos. Solo los errores de uso devuelven 2.
";

struct Opciones {
    urls: Vec<String>,
    archivo: Option<PathBuf>,
    json: bool,
    demo: bool,
    color: bool,
    ayuda: bool,
}

fn main() -> ExitCode {
    let argumentos: Vec<String> = env::args().skip(1).collect();
    match ejecutar(&argumentos) {
        Ok(codigo) => codigo,
        Err(error) => {
            eprintln!("phishing-analyzer: {error}");
            ExitCode::from(2)
        }
    }
}

fn ejecutar(argumentos: &[String]) -> Result<ExitCode, String> {
    let opciones = leer_opciones(argumentos)?;

    if opciones.ayuda {
        print!("{AYUDA}");
        return Ok(ExitCode::SUCCESS);
    }

    let mut urls: Vec<String> = opciones.urls.clone();
    if let Some(ruta) = &opciones.archivo {
        urls.extend(leer_enlaces(ruta)?);
    }
    let modo_demo = opciones.demo;
    if modo_demo {
        for caso in CASOS_DEMO {
            urls.push(caso.url.to_string());
        }
    }

    if urls.is_empty() {
        eprint!("{AYUDA}");
        return Ok(ExitCode::from(2));
    }

    let color = opciones.color && io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none();
    let informes: Vec<Informe> = urls.iter().map(|url| analizar(url)).collect();

    let salida = io::stdout();
    let mut salida = salida.lock();

    if opciones.json {
        let objetos: Vec<String> = informes.iter().map(|informe| informe.a_json()).collect();
        writeln!(salida, "[{}]", objetos.join(",")).map_err(|e| e.to_string())?;
        return Ok(ExitCode::SUCCESS);
    }

    for (indice, informe) in informes.iter().enumerate() {
        if indice > 0 {
            writeln!(salida).map_err(|e| e.to_string())?;
        }
        mostrar_informe(&mut salida, informe, color).map_err(|e| e.to_string())?;
    }

    if modo_demo {
        writeln!(salida).map_err(|e| e.to_string())?;
        mostrar_tabla(&mut salida, &informes, color).map_err(|e| e.to_string())?;
        writeln!(salida).map_err(|e| e.to_string())?;
        mostrar_notas(&mut salida).map_err(|e| e.to_string())?;
    }

    Ok(ExitCode::SUCCESS)
}

fn leer_opciones(argumentos: &[String]) -> Result<Opciones, String> {
    let mut opciones = Opciones {
        urls: Vec::new(),
        archivo: None,
        json: false,
        demo: false,
        color: true,
        ayuda: false,
    };

    let mut iterador = argumentos.iter();
    while let Some(argumento) = iterador.next() {
        match argumento.as_str() {
            "--json" => opciones.json = true,
            "--demo" => opciones.demo = true,
            "--no-color" => opciones.color = false,
            "--file" => {
                let ruta = iterador
                    .next()
                    .ok_or_else(|| "falta la ruta del archivo en --file".to_string())?;
                opciones.archivo = Some(PathBuf::from(ruta));
            }
            "-h" | "--help" => opciones.ayuda = true,
            otro if otro.starts_with("--") => {
                return Err(format!("opción desconocida: {otro}"));
            }
            otro => opciones.urls.push(otro.to_string()),
        }
    }

    Ok(opciones)
}

/// Lee los enlaces de un archivo: uno por línea, se ignoran las vacías y las de comentario.
fn leer_enlaces(ruta: &PathBuf) -> Result<Vec<String>, String> {
    let contenido =
        fs::read_to_string(ruta).map_err(|e| format!("no se pudo leer {}: {e}", ruta.display()))?;
    Ok(contenido
        .lines()
        .map(str::trim)
        .filter(|linea| !linea.is_empty() && !linea.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn pintar(color: bool, codigo: &str, texto: &str) -> String {
    if color {
        format!("{codigo}{texto}\x1b[0m")
    } else {
        texto.to_string()
    }
}

fn emoji(nivel: Nivel) -> &'static str {
    match nivel {
        Nivel::Bajo => "🟢",
        Nivel::Medio => "🟡",
        Nivel::Alto => "🔴",
    }
}

fn mostrar_informe(salida: &mut impl Write, informe: &Informe, color: bool) -> io::Result<()> {
    let nivel = pintar(color, informe.nivel.color(), informe.nivel.etiqueta());
    let plural = if informe.senales.len() == 1 { "" } else { "es" };
    let puntos = if informe.puntos == 1 {
        "punto"
    } else {
        "puntos"
    };
    writeln!(
        salida,
        "{} {} — {} {}, {} señal{}",
        emoji(informe.nivel),
        nivel,
        informe.puntos,
        puntos,
        informe.senales.len(),
        plural
    )?;
    writeln!(salida, "  {}", informe.url)?;
    writeln!(salida, "  dominio: {}", informe.dominio)?;

    let ancho = informe
        .senales
        .iter()
        .map(|senal| senal.codigo.len())
        .max()
        .unwrap_or(0);
    for senal in &informe.senales {
        let puntos = pintar(color, "\x1b[33m", &format!("+{}", senal.puntos));
        writeln!(
            salida,
            "    {}  {:<ancho$}  {}",
            puntos,
            senal.codigo,
            senal.detalle,
            ancho = ancho
        )?;
    }
    Ok(())
}

/// Tabla resumen de la demostración.
fn mostrar_tabla(salida: &mut impl Write, informes: &[Informe], color: bool) -> io::Result<()> {
    let ancho_url = informes
        .iter()
        .map(|informe| informe.url.len())
        .max()
        .unwrap_or(4)
        .max(4);

    writeln!(
        salida,
        "{:<ancho_url$}  {:<5}  {:>3}  SEÑALES",
        "URL",
        "NIVEL",
        "PTS",
        ancho_url = ancho_url
    )?;
    writeln!(salida, "{}", "-".repeat(ancho_url + 32))?;

    for informe in informes {
        let nivel = pintar(color, informe.nivel.color(), informe.nivel.etiqueta());
        let codigos: Vec<&str> = informe.senales.iter().map(|senal| senal.codigo).collect();
        writeln!(
            salida,
            "{:<ancho_url$}  {:<5}  {:>3}  {}",
            informe.url,
            nivel,
            informe.puntos,
            codigos.join(", "),
            ancho_url = ancho_url
        )?;
    }
    Ok(())
}

/// Explica cada caso al público.
fn mostrar_notas(salida: &mut impl Write) -> io::Result<()> {
    writeln!(salida, "Notas:")?;
    for caso in CASOS_DEMO {
        writeln!(salida, "  • {} → {}", caso.url, caso.nota)?;
    }
    Ok(())
}
