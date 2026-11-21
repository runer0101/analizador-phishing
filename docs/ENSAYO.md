# Guía de ensayo — Analizador de phishing

Objetivo: poder hacer la demostración **sin depender de internet** y con un video de
respaldo por si la sala falla.

## 1. Qué se necesita el día de la exposición

| Elemento | Para qué | ¿Necesita internet? |
| --- | --- | --- |
| `target/release/phishing-analyzer` | Analizador de phishing | No |
| Terminal con color | Legibilidad del veredicto | No |
| Video de respaldo (2 min) | Si la sala falla | No |
| Diapositivas en PDF | Por si el equipo del aula no abre Markdown | No |

**Si hay internet en el aula**, hay un extra: la misma herramienta está publicada en
<https://runer0101.github.io/analizador-phishing/>. Se puede abrir desde el móvil o el
proyector y enseñar que el análisis ocurre en el navegador del visitante. Es un
complemento: la demostración local **no** necesita internet.

El binario se compila **una vez antes** y se lleva en un pendrive:

```bash
cargo build --release
cp target/release/phishing-analyzer /media/USB/
```

## 2. Ensayo completo sin internet

Desconecte el cable de red o active el modo avión (la demo **no** necesita internet) y
ejecute:

```bash
scripts/demo.sh
```

Eso muestra los cinco casos de la demostración, un veredicto suelto y la salida JSON.

Si quiere comprobar de verdad que no hay red, puede ensayar en un espacio de nombres
aislado:

```bash
unshare -rn bash -c 'ip link set lo up; scripts/demo.sh'
```

## 3. Checklist antes de subir al aula

- [ ] `cargo build --release` terminó sin errores y el binario existe.
- [ ] `scripts/demo.sh` corrió completo y la tabla de veredictos sale con color.
- [ ] La tabla muestra `ALTO`, `MEDIO` y `BAJO` (los tres niveles).
- [ ] Video de respaldo grabado (ver más abajo) y guardado **también** en el pendrive.
- [ ] Diapositivas exportadas a PDF.
- [ ] Pendrive con: el binario, las diapositivas en PDF, el video y el repositorio.
- [ ] La segunda mitad de la exposición ensayada en el repositorio `honeypot-casero`.

## 4. Video de respaldo

Grabar con la herramienta del sistema (`Ctrl+Alt+Shift+R` en GNOME/KDE abre la grabación)
o con `asciinema` si lo tiene instalado:

```bash
asciinema rec demo.cast -c "scripts/demo.sh"
asciinema cat demo.cast   # reproducir
```

Grabe **la salida real**: la tabla de veredictos y el veredicto suelto. Dos minutos bastan.

## 5. Plan B si algo falla en el aula

| Fallo | Qué hacer |
| --- | --- |
| No hay color en la pantalla | `NO_COLOR=1 scripts/demo.sh` (el texto sigue siendo legible) |
| El binario no arranca en el equipo del aula | usar el video de respaldo |
| La sala no tiene internet | no importa: el analizador no usa internet |

## 6. Aviso para la exposición

El analizador **no abre ninguna conexión**: trabaja sobre el texto del enlace que se le
entrega. Es la primera de las dos herramientas; la segunda es el honeypot casero del
repositorio `honeypot-casero`.
