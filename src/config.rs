//! Datos de las reglas: las cuatro listas que se pueden editar sin tocar el código.
//!
//! Los archivos de `datos/` vienen **embebidos en el binario** con `include_str!`, así
//! que al ejecutar el programa no hace falta ningún archivo suelto: todo viaja dentro.
//!
//! Cada lista se lee **una sola vez**, la primera vez que se usa, y se guarda en un
//! `OnceLock`. A partir de ahí, cada llamada es solo leer un puntero: no se vuelve a
//! construir ni a reservar memoria.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

/// Palabras de gancho: las que buscan la confianza de la persona.
const PALABRAS_GANCHO: &str = include_str!("../datos/palabras_gancho.txt");

/// Acortadores de enlaces: esconden el destino real.
const ACORTADORES: &str = include_str!("../datos/acortadores.txt");

/// Terminaciones poco confiables: baratas de comprar, comunes en el estafa.
const TERMINACIONES: &str = include_str!("../datos/terminaciones.txt");

/// Marcas vigiladas y su sitio oficial.
const MARCAS: &str = include_str!("../datos/marcas.txt");

/// Cuenta cuántas veces se han construido las listas. Solo se usa en las pruebas.
static CONSTRUCCIONES: AtomicUsize = AtomicUsize::new(0);

static PALABRAS: OnceLock<Vec<String>> = OnceLock::new();
static ACORTADOR: OnceLock<Vec<String>> = OnceLock::new();
static TERMINACION: OnceLock<Vec<String>> = OnceLock::new();
static MARCA: OnceLock<Vec<(String, String)>> = OnceLock::new();

/// Las palabras de gancho, ya cargadas.
pub fn palabras_gancho() -> &'static [String] {
    PALABRAS.get_or_init(|| valores(PALABRAS_GANCHO))
}

/// Los acortadores, ya cargados.
pub fn acortadores() -> &'static [String] {
    ACORTADOR.get_or_init(|| valores(ACORTADORES))
}

/// Las terminaciones poco confiables, ya cargadas.
pub fn terminaciones() -> &'static [String] {
    TERMINACION.get_or_init(|| valores(TERMINACIONES))
}

/// Las marcas vigiladas con su sitio oficial, ya cargadas.
pub fn marcas() -> &'static [(String, String)] {
    MARCA.get_or_init(|| pares(MARCAS))
}

/// Cuántas veces se han construido las listas. Sirve para probar que es una sola vez.
pub fn construcciones() -> usize {
    CONSTRUCCIONES.load(Ordering::Relaxed)
}

/// Lee una lista de valores: una por línea, con «#» para comentar.
fn valores(contenido: &str) -> Vec<String> {
    CONSTRUCCIONES.fetch_add(1, Ordering::Relaxed);
    contenido
        .lines()
        .map(str::trim)
        .filter(|linea| !linea.is_empty() && !linea.starts_with('#'))
        .filter_map(|linea| campos(linea).first().map(|valor| valor.to_string()))
        .collect()
}

/// Lee una lista de pares: «clave | valor» en cada línea.
fn pares(contenido: &str) -> Vec<(String, String)> {
    CONSTRUCCIONES.fetch_add(1, Ordering::Relaxed);
    contenido
        .lines()
        .map(str::trim)
        .filter(|linea| !linea.is_empty() && !linea.starts_with('#'))
        .filter_map(|linea| {
            let campos = campos(linea);
            match (campos.first(), campos.get(1)) {
                (Some(primero), Some(segundo)) => Some((primero.to_string(), segundo.to_string())),
                _ => None,
            }
        })
        .collect()
}

/// Divide una línea en sus campos, separados por «|».
fn campos(linea: &str) -> Vec<&str> {
    linea
        .split('|')
        .map(str::trim)
        .filter(|campo| !campo.is_empty())
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn las_listas_se_cargan_una_sola_vez() {
        // Primero se fuerzan las cuatro: así, a partir de aquí, ya ninguna se vuelve a
        // construir y la comparación es exacta.
        let _ = palabras_gancho();
        let _ = acortadores();
        let _ = terminaciones();
        let _ = marcas();

        let antes = construcciones();
        for _ in 0..1000 {
            let _ = palabras_gancho();
            let _ = acortadores();
            let _ = terminaciones();
            let _ = marcas();
        }
        let despues = construcciones();

        assert_eq!(
            antes, despues,
            "una lista se construyó más de una vez ({antes} → {despues})"
        );
    }

    #[test]
    fn las_listas_apuntan_siempre_al_mismo_lugar() {
        let primera = palabras_gancho().as_ptr();
        let segunda = palabras_gancho().as_ptr();
        assert_eq!(primera, segunda, "la lista se reconstruyó en memoria");
    }

    #[test]
    fn las_listas_tienen_el_contenido_esperado() {
        assert!(palabras_gancho().iter().any(|p| p == "login"));
        assert!(acortadores().iter().any(|a| a == "bit.ly"));
        assert!(terminaciones().iter().any(|t| t == ".xyz"));
        assert!(marcas()
            .iter()
            .any(|(marca, oficial)| marca == "paypal" && oficial == "paypal.com"));
    }

    #[test]
    fn los_bancos_bolivianos_estan_en_el_archivo_de_marcas() {
        for esperada in ["bcp", "bnb", "bancounion", "mercantilsantacruz"] {
            assert!(
                marcas().iter().any(|(marca, _)| marca == esperada),
                "falta la marca {esperada}"
            );
        }
    }

    #[test]
    fn los_comentarios_de_los_archivos_no_se_cargan_como_datos() {
        assert!(!palabras_gancho().iter().any(|p| p.starts_with('#')));
        assert!(!acortadores().iter().any(|a| a.starts_with('#')));
        assert!(!terminaciones().iter().any(|t| t.starts_with('#')));
        assert!(!marcas().iter().any(|(marca, _)| marca.starts_with('#')));
    }
}
