// Analizador de phishing en el navegador.
//
// El motor de reglas está compilado a WebAssembly: el análisis ocurre en el equipo del
// visitante y el enlace no sale de ahí. La comunicación con el módulo es mínima:
// reservar memoria, escribir el texto, pedir el veredicto en JSON y devolver la memoria.

const CASOS = [
  { url: "http://paypa1.com/login/verify", nota: "typosquatting de PayPal" },
  { url: "http://paypal.secure-verify-login.com/account", nota: "imita a PayPal" },
  { url: "http://192.168.56.101/wp-login.php", nota: "login desde una IP cruda" },
  { url: "https://www.bancounion.com.bo/verificacion-clave", nota: "sitio real (falso positivo)" },
  { url: "https://www.bancounion.com.bo/", nota: "sitio real del banco" },
  { url: "https://www.google.com", nota: "sitio legítimo" },
];

// Nombre legible de cada señal, para que se lea sin saber de código.
const ETIQUETAS = {
  sin_https: "No usa HTTPS",
  ip_dominio: "IP en lugar de dominio",
  usuario_oculto: "El «@» que esconde el destino",
  subdominios: "Demasiados subdominios",
  letras_camufladas: "Letras camufladas",
  acortador: "Link acortado",
  terminacion_rara: "Terminación poco confiable",
  guiones: "Muchos guiones en el dominio",
  palabra_gancho: "Palabra de gancho",
  marca_falsa: "Usa el nombre de una marca",
  typosquatting: "Imita a una marca (typosquatting)",
};

const NIVELES = {
  alto: { etiqueta: "ALTO", clase: "alto" },
  medio: { etiqueta: "MEDIO", clase: "medio" },
  bajo: { etiqueta: "BAJO", clase: "bajo" },
};

const formulario = document.getElementById("formulario");
const campoEnlace = document.getElementById("enlace");
const estado = document.getElementById("estado");
const resultado = document.getElementById("resultado");
const listaCasos = document.getElementById("casos");

let modulo = null;

async function iniciar() {
  estado.textContent = "Cargando el motor de análisis…";
  const respuesta = await fetch("phishing_analyzer.wasm");
  const bytes = await respuesta.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, {});
  modulo = instance.exports;
  estado.textContent = "";
  formulario.querySelector("button").disabled = false;
}

/** Analiza el enlace y devuelve el veredicto en JSON. */
function analizarEnlace(url) {
  const bytes = new TextEncoder().encode(url);
  const puntero = modulo.wasm_asignar_memoria(bytes.length);
  new Uint8Array(modulo.memory.buffer).set(bytes, puntero);

  const veredicto = modulo.wasm_analizar(puntero, bytes.length);
  const largo = modulo.wasm_ultimo_tamano();
  const json = new TextDecoder().decode(
    new Uint8Array(modulo.memory.buffer, veredicto, largo)
  );

  // Se devuelve la memoria: sin esto, cada análisis dejaría su JSON en el navegador.
  modulo.wasm_liberar_resultado(veredicto, largo);
  modulo.wasm_liberar_memoria(puntero, bytes.length);

  const datos = JSON.parse(json);
  // El motor devuelve un aviso (no un veredicto) cuando el texto no es UTF-8 válido.
  if (datos.error) {
    throw new Error(datos.error);
  }
  return datos;
}

function crear(nodo, texto, clase) {
  const elemento = document.createElement(nodo);
  if (texto !== undefined) elemento.textContent = texto;
  if (clase) elemento.className = clase;
  return elemento;
}

function pintar(datos) {
  resultado.replaceChildren();
  resultado.hidden = false;
  const nivel = NIVELES[datos.nivel] || { etiqueta: "—", clase: "" };

  const veredicto = crear("div", undefined, "veredicto");
  veredicto.append(crear("span", nivel.etiqueta, `insignia ${nivel.clase}`));
  veredicto.append(crear("span", `${datos.puntos} puntos`, "puntaje"));
  veredicto.append(crear("span", datos.dominio, "dominio"));
  resultado.append(veredicto);

  if (datos.senales.length === 0) {
    resultado.append(crear("p", "Ninguna señal sospechosa.", "nota"));
    return;
  }

  const tabla = crear("table", undefined, "tabla señales");
  const cabecera = crear("thead");
  const filaCabecera = crear("tr");
  const celdaSenal = crear("th", "Señal");
  celdaSenal.scope = "col";
  const celdaPuntos = crear("th", "Puntos", "num");
  celdaPuntos.scope = "col";
  const celdaDetalle = crear("th", "Detalle");
  celdaDetalle.scope = "col";
  filaCabecera.append(celdaSenal, celdaPuntos, celdaDetalle);
  cabecera.append(filaCabecera);
  tabla.append(cabecera);

  const cuerpo = crear("tbody");
  for (const senal of datos.senales) {
    const fila = crear("tr");
    const celdaNombre = crear("td");
    celdaNombre.append(crear("strong", ETIQUETAS[senal.codigo] || senal.codigo));
    celdaNombre.append(crear("br"));
    celdaNombre.append(crear("code", senal.codigo));
    fila.append(celdaNombre);
    fila.append(crear("td", `+${senal.puntos}`, "num"));
    fila.append(crear("td", senal.detalle));
    cuerpo.append(fila);
  }
  tabla.append(cuerpo);
  resultado.append(tabla);
}

function procesar(url) {
  if (!modulo) {
    estado.textContent = "El motor todavía está cargando.";
    return;
  }
  estado.textContent = "";
  estado.classList.remove("error");
  try {
    pintar(analizarEnlace(url));
  } catch (error) {
    resultado.replaceChildren();
    resultado.hidden = true;
    estado.textContent = `No se pudo analizar: ${error.message}`;
    estado.classList.add("error");
  }
}

formulario.addEventListener("submit", (evento) => {
  evento.preventDefault();
  const url = campoEnlace.value.trim();
  if (url) procesar(url);
});

for (const caso of CASOS) {
  const boton = crear("button", caso.url);
  boton.type = "button";
  boton.title = caso.nota;
  boton.addEventListener("click", () => {
    campoEnlace.value = caso.url;
    procesar(caso.url);
  });
  const elemento = crear("li");
  elemento.append(boton);
  listaCasos.append(elemento);
}

iniciar().catch((error) => {
  estado.textContent = `No se pudo cargar el motor de análisis: ${error.message}`;
  estado.classList.add("error");
});
