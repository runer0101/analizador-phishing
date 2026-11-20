//! Command line interface of the phishing analyzer.

use phishing_analyzer::{analyze, Level, Report, DEMO_CASES};
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
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

struct Options {
    urls: Vec<String>,
    file: Option<PathBuf>,
    json: bool,
    demo: bool,
    color: bool,
    help: bool,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("phishing-analyzer: {err}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let options = parse_args(args)?;

    if options.help {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    let mut urls: Vec<String> = options.urls.clone();
    if let Some(path) = &options.file {
        urls.extend(read_links(path)?);
    }
    let demo_mode = options.demo;
    if demo_mode {
        for case in DEMO_CASES {
            urls.push(case.url.to_string());
        }
    }

    if urls.is_empty() {
        eprint!("{USAGE}");
        return Ok(ExitCode::from(2));
    }

    let color = options.color && io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none();
    let reports: Vec<Report> = urls.iter().map(|url| analyze(url)).collect();

    let stdout = io::stdout();
    let mut out = stdout.lock();

    if options.json {
        let items: Vec<String> = reports.iter().map(|r| r.to_json()).collect();
        writeln!(out, "[{}]", items.join(",")).map_err(|e| e.to_string())?;
        return Ok(ExitCode::SUCCESS);
    }

    for (index, report) in reports.iter().enumerate() {
        if index > 0 {
            writeln!(out).map_err(|e| e.to_string())?;
        }
        print_report(&mut out, report, color).map_err(|e| e.to_string())?;
    }

    if demo_mode {
        writeln!(out).map_err(|e| e.to_string())?;
        print_table(&mut out, &reports, color).map_err(|e| e.to_string())?;
        writeln!(out).map_err(|e| e.to_string())?;
        print_notes(&mut out).map_err(|e| e.to_string())?;
    }

    Ok(ExitCode::SUCCESS)
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        urls: Vec::new(),
        file: None,
        json: false,
        demo: false,
        color: true,
        help: false,
    };

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => options.json = true,
            "--demo" => options.demo = true,
            "--no-color" => options.color = false,
            "--file" => {
                let path = iter
                    .next()
                    .ok_or_else(|| "falta la ruta del archivo en --file".to_string())?;
                options.file = Some(PathBuf::from(path));
            }
            "-h" | "--help" => options.help = true,
            other if other.starts_with("--") => {
                return Err(format!("opción desconocida: {other}"));
            }
            other => options.urls.push(other.to_string()),
        }
    }

    Ok(options)
}

/// Lee los enlaces de un archivo: uno por línea, se ignoran las vacías y las de comentario.
fn read_links(path: &PathBuf) -> Result<Vec<String>, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("no se pudo leer {}: {e}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("{code}{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn emoji(level: Level) -> &'static str {
    match level {
        Level::Low => "🟢",
        Level::Medium => "🟡",
        Level::High => "🔴",
    }
}

fn print_report(out: &mut impl Write, report: &Report, color: bool) -> io::Result<()> {
    let level_text = paint(color, report.level.color(), report.level.label());
    let plural = if report.reasons.len() == 1 { "" } else { "es" };
    let points = if report.score == 1 { "pt" } else { "pts" };
    writeln!(
        out,
        "{} {} — {} {}, {} señal{}",
        emoji(report.level),
        level_text,
        report.score,
        points,
        report.reasons.len(),
        plural
    )?;
    writeln!(out, "  {}", report.input)?;
    writeln!(out, "  dominio: {}", report.host)?;

    let width = report
        .reasons
        .iter()
        .map(|r| r.code.len())
        .max()
        .unwrap_or(0);
    for reason in &report.reasons {
        let points = paint(color, "\x1b[33m", &format!("+{}", reason.points));
        writeln!(
            out,
            "    {}  {:<width$}  {}",
            points,
            reason.code,
            reason.detail,
            width = width
        )?;
    }
    Ok(())
}

/// Tabla resumen de la demostración.
fn print_table(out: &mut impl Write, reports: &[Report], color: bool) -> io::Result<()> {
    let url_width = reports
        .iter()
        .map(|r| r.input.len())
        .max()
        .unwrap_or(4)
        .max(4);

    writeln!(
        out,
        "{:<url_width$}  {:<5}  {:>3}  SEÑALES",
        "URL",
        "NIVEL",
        "PTS",
        url_width = url_width
    )?;
    writeln!(out, "{}", "-".repeat(url_width + 32))?;

    for report in reports {
        let level = paint(color, report.level.color(), report.level.label());
        let codes: Vec<&str> = report.reasons.iter().map(|r| r.code).collect();
        writeln!(
            out,
            "{:<url_width$}  {:<5}  {:>3}  {}",
            report.input,
            level,
            report.score,
            codes.join(", "),
            url_width = url_width
        )?;
    }
    Ok(())
}

/// Explica cada caso al público.
fn print_notes(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Notas:")?;
    for case in DEMO_CASES {
        writeln!(out, "  • {} → {}", case.url, case.note)?;
    }
    Ok(())
}
