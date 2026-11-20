// Analizador de phishing en el navegador.
//
// El motor de reglas está compilado a WebAssembly: el análisis ocurre en el equipo del
// visitante y el enlace no sale de ahí. La comunicación con el módulo es mínima: reservar
// memoria, escribir el texto, pedir el veredicto en JSON y liberarla.

const CASOS = [
  { url: "http://paypa1.com/login/verify", nota: "typosquatting de PayPal" },
  { url: "http://paypal.secure-verify-login.com/account", nota: "imita a PayPal" },
  { url: "http://192.168.56.101/wp-login.php", nota: "login desde una IP cruda" },
  { url: "https://www.bancounion.com.bo/verificacion-clave", nota: "sitio real (falso positivo)" },
  { url: "https://www.google.com", nota: "sitio legítimo" },
];

const NIVELES = {
  high: { etiqueta: "ALTO", clase: "alto" },
  medium: { etiqueta: "MEDIO", clase: "medio" },
  low: { etiqueta: "BAJO", clase: "bajo" },
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
function analizar(url) {
  const bytes = new TextEncoder().encode(url);
  const puntero = modulo.wasm_alloc(bytes.length);
  new Uint8Array(modulo.memory.buffer).set(bytes, puntero);

  const resultadoPtr = modulo.wasm_analyze(puntero, bytes.length);
  const largo = modulo.wasm_last_len();
  const json = new TextDecoder().decode(
    new Uint8Array(modulo.memory.buffer, resultadoPtr, largo)
  );

  modulo.wasm_dealloc(puntero, bytes.length);
  return JSON.parse(json);
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
  const nivel = NIVELES[datos.level] || { etiqueta: "—", clase: "" };

  const veredicto = crear("div", undefined, "veredicto");
  veredicto.append(crear("span", nivel.etiqueta, `insignia ${nivel.clase}`));
  veredicto.append(crear("span", `${datos.score} puntos`, "puntaje"));
  veredicto.append(crear("span", datos.host, "dominio"));
  resultado.append(veredicto);

  if (datos.reasons.length === 0) {
    resultado.append(crear("p", "Ninguna señal sospechosa.", "nota"));
    return;
  }

  const tabla = crear("table", undefined, "tabla señales");
  const cabecera = crear("thead");
  const filaCabecera = crear("tr");
  filaCabecera.append(crear("th", "Señal"), crear("th", "Puntos", "num"), crear("th", "Detalle"));
  cabecera.append(filaCabecera);
  tabla.append(cabecera);

  const cuerpo = crear("tbody");
  for (const razon of datos.reasons) {
    const fila = crear("tr");
    const celdaCodigo = crear("td");
    celdaCodigo.append(crear("code", razon.code));
    fila.append(celdaCodigo);
    fila.append(crear("td", `+${razon.points}`, "num"));
    fila.append(crear("td", razon.detail));
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
    pintar(analizar(url));
  } catch (error) {
    resultado.replaceChildren();
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
