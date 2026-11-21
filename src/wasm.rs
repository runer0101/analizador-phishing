//! Frontera entre Rust y JavaScript para la demostración del navegador.
//!
//! El motor de reglas es lógica de texto puro: no usa archivos, ni reloj, ni red. Por
//! eso se puede compilar para WebAssembly y la página puede analizar el enlace **en el
//! equipo del visitante**. Este módulo es toda la frontera entre Rust y JavaScript:
//!
//! - `wasm_asignar_memoria(tamano)`: reserva memoria y devuelve la dirección.
//! - `wasm_analizar(puntero, tamano)`: analiza el texto UTF-8 y devuelve la dirección del
//!   veredicto en JSON.
//! - `wasm_ultimo_tamano()`: devuelve el largo de ese JSON.
//! - `wasm_liberar_resultado(puntero, tamano)`: devuelve la memoria del veredicto.
//! - `wasm_liberar_memoria(puntero, tamano)`: devuelve la memoria reservada para escribir.
//!
//! La página nunca manda el enlace a ningún servidor: todo ocurre en el navegador.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::analizar;

/// Largo del JSON que produjo la última llamada a [`wasm_analizar`].
static ULTIMO_TAMANO: AtomicUsize = AtomicUsize::new(0);

/// Reserva `tamano` bytes de memoria para que JavaScript escriba el enlace.
#[no_mangle]
pub extern "C" fn wasm_asignar_memoria(tamano: usize) -> *mut u8 {
    let mut buffer = vec![0u8; tamano];
    let puntero = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    puntero
}

/// Devuelve la memoria reservada con [`wasm_asignar_memoria`].
///
/// # Seguridad
/// `puntero` debe venir de [`wasm_asignar_memoria`] con el mismo `tamano`.
#[no_mangle]
pub unsafe extern "C" fn wasm_liberar_memoria(puntero: *mut u8, tamano: usize) {
    if puntero.is_null() {
        return;
    }
    drop(Vec::from_raw_parts(puntero, 0, tamano));
}

/// Veredicto que se devuelve cuando el texto recibido no es UTF-8 válido.
///
/// Lleva la misma forma que el informe normal, con una clave `error` extra: la página
/// la lee y la muestra como aviso.
const ERROR_UTF8: &str = r#"{"url":"","dominio":"","nivel":"","puntos":0,"senales":[],"error":"El enlace recibido no es texto UTF-8 válido"}"#;

/// Analiza el texto UTF-8 que está en `puntero` y devuelve la dirección del JSON.
///
/// El texto se valida antes de usarlo: `from_utf8_unchecked` con una entrada inválida
/// sería comportamiento indefinido, y aquí la entrada viene de JavaScript.
///
/// # Seguridad
/// `puntero` debe apuntar a `tamano` bytes legibles.
#[no_mangle]
pub unsafe extern "C" fn wasm_analizar(puntero: *const u8, tamano: usize) -> *const u8 {
    let json = match std::str::from_utf8(std::slice::from_raw_parts(puntero, tamano)) {
        Ok(texto) => analizar(texto).a_json().into_bytes(),
        Err(_) => ERROR_UTF8.as_bytes().to_vec(),
    };
    ULTIMO_TAMANO.store(json.len(), Ordering::Relaxed);
    let caja: Box<[u8]> = json.into_boxed_slice();
    Box::into_raw(caja) as *mut u8
}

/// Largo en bytes del JSON que devolvió la última llamada a [`wasm_analizar`].
#[no_mangle]
pub extern "C" fn wasm_ultimo_tamano() -> usize {
    ULTIMO_TAMANO.load(Ordering::Relaxed)
}

/// Devuelve la memoria del veredicto que devolvió [`wasm_analizar`].
///
/// Sin esto, cada análisis dejaría su JSON en la memoria del navegador para siempre.
///
/// # Seguridad
/// `puntero` y `tamano` deben ser los que devolvió [`wasm_analizar`].
#[no_mangle]
pub unsafe extern "C" fn wasm_liberar_resultado(puntero: *mut u8, tamano: usize) {
    if puntero.is_null() || tamano == 0 {
        return;
    }
    drop(Box::from_raw(std::slice::from_raw_parts_mut(
        puntero, tamano,
    )));
}
