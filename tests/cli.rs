//! Integration tests of the `phishing-analyzer` binary.

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_phishing-analyzer"))
        .args(args)
        .output()
        .expect("no se pudo ejecutar el binario");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn demo_prints_the_five_cases() {
    let (code, stdout, _) = run(&["--demo"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("paypa1.com"),
        "falta el caso de typosquatting"
    );
    assert!(stdout.contains("ALTO"), "falta el veredicto ALTO");
    assert!(stdout.contains("BAJO"), "falta el veredicto BAJO");
    assert!(stdout.contains("SEÑALES"), "falta la tabla resumen");
}

#[test]
fn without_arguments_prints_usage_and_fails() {
    let (code, stdout, stderr) = run(&[]);
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(stderr.contains("Uso:"), "falta el mensaje de uso");
}

#[test]
fn unknown_option_fails() {
    let (code, _, stderr) = run(&["--inventado"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("opción desconocida"));
}

#[test]
fn json_output_is_an_array_with_one_object_per_link() {
    let (code, stdout, _) = run(&[
        "--json",
        "http://paypa1.com/login/verify",
        "https://www.google.com",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.trim_start().starts_with('['));
    assert!(stdout.trim_end().ends_with(']'));
    assert!(stdout.contains("\"level\":\"high\""));
    assert!(stdout.contains("\"level\":\"low\""));
    assert_eq!(stdout.matches("\"url\":").count(), 2);
}

#[test]
fn no_color_removes_the_ansi_sequences() {
    let (code, stdout, _) = run(&["--no-color", "http://paypa1.com/login/verify"]);
    assert_eq!(code, 0);
    assert!(
        !stdout.contains('\x1b'),
        "quedaron secuencias ANSI en la salida"
    );
    assert!(stdout.contains("ALTO"));
}

#[test]
fn a_suspicious_link_still_exits_with_zero() {
    let (code, _, _) = run(&["http://paypa1.com/login/verify"]);
    assert_eq!(code, 0, "el veredicto es información, no un fallo");
}

#[test]
fn reads_links_from_a_file() {
    let dir = std::env::temp_dir().join("phishing-analyzer-cli-test");
    std::fs::create_dir_all(&dir).expect("no se pudo crear el directorio temporal");
    let path = dir.join("enlaces.txt");
    std::fs::write(
        &path,
        "# comentario\nhttp://paypa1.com/login/verify\n\nhttps://www.google.com\n",
    )
    .expect("no se pudo escribir el archivo");

    let (code, stdout, _) = run(&["--file", path.to_str().unwrap(), "--json"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout.matches("\"url\":").count(),
        2,
        "las líneas vacías y comentarios se ignoran"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn missing_file_fails_with_a_clear_message() {
    let (code, _, stderr) = run(&["--file", "/no/existe/enlaces.txt"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("no se pudo leer"));
}
