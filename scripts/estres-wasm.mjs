// Test de estrés del módulo WebAssembly: 1000 análisis seguidos, mirando que la memoria
// del navegador no crezca sin control (una fuga).
//
// Uso:  node scripts/estres-wasm.mjs [ruta/al/phishing_analyzer.wasm]
//
// La idea: la memoria del módulo puede crecer un poco (el asignador de Rust agrupa la
// memoria y no la devuelve al sistema). Lo que no puede pasar es que crezca de forma
// lineal: eso sería una fuga. Por eso se mide después de 1000 análisis y después de 5000,
// y se mira cuánto crece de más en los 4000 siguientes.

import { readFile } from "node:fs/promises";

const ruta =
  process.argv[2] ?? "target/wasm32-unknown-unknown/release/phishing_analyzer.wasm";
const PAGINA = 64 * 1024; // 64 KB: el tamaño de una página de memoria.
const TOLERANCIA = 4 * PAGINA; // se tolera hasta 4 páginas de crecimiento.

const bytes = await readFile(ruta);
const { instance } = await WebAssembly.instantiate(bytes, {});
const modulo = instance.exports;

const enlace = new TextEncoder().encode("http://paypa1.com/login/verify");

/** Analiza un enlace y devuelve la memoria del módulo, en bytes. */
function analizar() {
  const puntero = modulo.wasm_asignar_memoria(enlace.length);
  new Uint8Array(modulo.memory.buffer).set(enlace, puntero);
  const veredicto = modulo.wasm_analizar(puntero, enlace.length);
  const largo = modulo.wasm_ultimo_tamano();
  new TextDecoder().decode(new Uint8Array(modulo.memory.buffer, veredicto, largo));
  // Lo importante: se devuelve la memoria de los dos lados.
  modulo.wasm_liberar_resultado(veredicto, largo);
  modulo.wasm_liberar_memoria(puntero, enlace.length);
}

/** Analiza `cuantas` veces y devuelve la memoria que ocupa el módulo. */
function medir(cuantas) {
  for (let i = 0; i < cuantas; i++) analizar();
  return modulo.memory.buffer.byteLength;
}

analizar(); // calentar: la primera llamada agranda la memoria.
const inicial = modulo.memory.buffer.byteLength;

const trasMil = medir(1000);
const trasCincoMil = medir(4000);
const crecimiento = trasCincoMil - trasMil;

console.log(`memoria inicial:            ${inicial} bytes`);
console.log(`después de 1000 análisis:   ${trasMil} bytes`);
console.log(`después de 5000 análisis:   ${trasCincoMil} bytes`);
console.log(`crecimiento entre ambos:    ${crecimiento} bytes`);

if (crecimiento > TOLERANCIA) {
  console.error(
    `FALLO: la memoria crece ${crecimiento} bytes en 4000 análisis: hay una fuga.`
  );
  process.exit(1);
}

console.log("OK: 1000 análisis (y 5000 en total) sin fuga de memoria.");
