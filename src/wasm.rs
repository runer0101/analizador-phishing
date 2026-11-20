//! WebAssembly ABI for the browser demo.
//!
//! The rules engine is pure text logic: no files, no clock, no network. That makes it
//! portable to `wasm32-unknown-unknown`, where the demo page analyses a link inside the
//! visitor's browser. This module is the thin boundary between Rust and JavaScript:
//!
//! - `wasm_alloc(len)` reserves `len` bytes of memory and returns the pointer.
//! - `wasm_analyze(ptr, len)` analyses the UTF-8 text at that pointer and returns a
//!   pointer to the JSON verdict.
//! - `wasm_last_len()` returns the length of that JSON.
//! - `wasm_dealloc(ptr, len)` releases the memory reserved with `wasm_alloc`.
//!
//! The page never sends the link anywhere: the analysis happens locally, in the browser.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::analyze;

/// Length of the JSON produced by the last call to [`wasm_analyze`].
static LAST_LEN: AtomicUsize = AtomicUsize::new(0);

/// Reserves `len` bytes of memory for the caller to write into.
#[no_mangle]
pub extern "C" fn wasm_alloc(len: usize) -> *mut u8 {
    let mut buffer = vec![0u8; len];
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    pointer
}

/// Releases memory reserved with [`wasm_alloc`].
///
/// # Safety
/// `pointer` must come from [`wasm_alloc`] with the same `len`.
#[no_mangle]
pub unsafe extern "C" fn wasm_dealloc(pointer: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(pointer, 0, len));
}

/// Analyses the UTF-8 text at `pointer` and returns a pointer to the JSON verdict.
///
/// # Safety
/// `pointer` must point to `len` readable bytes of valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn wasm_analyze(pointer: *const u8, len: usize) -> *const u8 {
    let input = std::str::from_utf8_unchecked(std::slice::from_raw_parts(pointer, len));
    let json = analyze(input).to_json().into_bytes();
    LAST_LEN.store(json.len(), Ordering::Relaxed);
    let mut boxed = json.into_boxed_slice();
    let pointer = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    pointer
}

/// Length in bytes of the JSON returned by the last [`wasm_analyze`].
#[no_mangle]
pub extern "C" fn wasm_last_len() -> usize {
    LAST_LEN.load(Ordering::Relaxed)
}
