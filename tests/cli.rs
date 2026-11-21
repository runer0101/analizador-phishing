//! Pruebas de la línea de órdenes: se ejecuta el binario de verdad y se mira lo que
//! imprime y con qué código de salida termina.

use std::process::Command;

fn ejecutar(argumentos: &[&str]) -> (i32, String, String) {
    let salida = Command::new(env!("CARGO_BIN_EXE_phishing-analyzer"))
        .args(argumentos)
        .output()
        .expect("no se pudo ejecutar el binario");
    (
        salida.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&salida.stdout).to_string(),
        String::from_utf8_lossy(&salida.stderr).to_string(),
    )
}

#[test]
fn la_demo_muestra_los_cinco_casos() {
    let (codigo, salida, _) = ejecutar(&["--demo"]);
    assert_eq!(codigo, 0);
    assert!(
        salida.contains("paypa1.com"),
        "falta el caso de typosquatting"
    );
    assert!(salida.contains("ALTO"), "falta el veredicto ALTO");
    assert!(salida.contains("BAJO"), "falta el veredicto BAJO");
    assert!(salida.contains("SEÑALES"), "falta la tabla resumen");
}

#[test]
fn sin_argumentos_muestra_el_uso_y_falla() {
    let (codigo, salida, error) = ejecutar(&[]);
    assert_eq!(codigo, 2);
    assert!(salida.is_empty());
    assert!(error.contains("Uso:"), "falta el mensaje de uso");
}

#[test]
fn una_opcion_inventada_falla() {
    let (codigo, _, error) = ejecutar(&["--inventado"]);
    assert_eq!(codigo, 2);
    assert!(error.contains("opción desconocida"));
}

#[test]
fn el_json_tiene_un_objeto_por_enlace() {
    let (codigo, salida, _) = ejecutar(&[
        "--json",
        "http://paypa1.com/login/verify",
        "https://www.google.com",
    ]);
    assert_eq!(codigo, 0);
    assert!(salida.trim_start().starts_with('['));
    assert!(salida.trim_end().ends_with(']'));
    assert!(salida.contains("\"nivel\":\"alto\""));
    assert!(salida.contains("\"nivel\":\"bajo\""));
    assert_eq!(salida.matches("\"url\":").count(), 2);
}

#[test]
fn el_json_usa_las_claves_en_espanol() {
    let (_, salida, _) = ejecutar(&["--json", "http://paypa1.com/login/verify"]);
    assert!(salida.contains("\"dominio\":\"paypa1.com\""));
    assert!(salida.contains("\"puntos\":5"));
    assert!(salida.contains("\"senales\":["));
    assert!(salida.contains("\"codigo\":\"typosquatting\""));
}

#[test]
fn sin_color_no_quedan_secuencias_ansi() {
    let (codigo, salida, _) = ejecutar(&["--no-color", "http://paypa1.com/login/verify"]);
    assert_eq!(codigo, 0);
    assert!(
        !salida.contains('\x1b'),
        "quedaron secuencias ANSI en la salida"
    );
    assert!(salida.contains("ALTO"));
}

#[test]
fn un_enlace_sospechoso_no_es_un_error() {
    let (codigo, _, _) = ejecutar(&["http://paypa1.com/login/verify"]);
    assert_eq!(codigo, 0, "el veredicto es información, no un fallo");
}

#[test]
fn lee_los_enlaces_de_un_archivo() {
    let carpeta = std::env::temp_dir().join("pruebas-cli-analizador");
    std::fs::create_dir_all(&carpeta).expect("no se pudo crear la carpeta temporal");
    let ruta = carpeta.join("enlaces.txt");
    std::fs::write(
        &ruta,
        "# comentario\nhttp://paypa1.com/login/verify\n\nhttps://www.google.com\n",
    )
    .expect("no se pudo escribir el archivo");

    let (codigo, salida, _) = ejecutar(&["--file", ruta.to_str().unwrap(), "--json"]);
    assert_eq!(codigo, 0);
    assert_eq!(
        salida.matches("\"url\":").count(),
        2,
        "las líneas vacías y los comentarios se ignoran"
    );

    let _ = std::fs::remove_file(&ruta);
}

#[test]
fn un_archivo_que_no_existe_falla_con_un_mensaje_claro() {
    let (codigo, _, error) = ejecutar(&["--file", "/no/existe/enlaces.txt"]);
    assert_eq!(codigo, 2);
    assert!(error.contains("no se pudo leer"));
}

#[test]
fn una_entrada_vacia_no_hace_fallar_al_programa() {
    let (codigo, salida, error) = ejecutar(&[""]);
    assert_eq!(codigo, 0);
    assert!(error.is_empty());
    assert!(salida.contains("BAJO"));
}

#[test]
fn los_casos_limite_no_hacen_fallar_al_programa() {
    let casos = [
        "http://",
        "http:///paypa1.com/login",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://banco.com%40malo.com/",
        "http://p\u{0430}ypal.com/",
        "http://exa mple.com/",
        "http://[",
        "http://xn--pypal-4ve.com/",
    ];
    for caso in casos {
        let (codigo, _, error) = ejecutar(&[caso]);
        assert_eq!(codigo, 0, "entrada: {caso}");
        assert!(error.is_empty(), "entrada: {caso} → {error}");
    }
}
