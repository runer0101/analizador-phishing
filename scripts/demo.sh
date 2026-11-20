#!/usr/bin/env bash
# Demostración del analizador de phishing.
#
# No necesita internet: el analizador lee el enlace como texto y nunca lo visita.

set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"

BIN="$RAIZ/target/release/phishing-analyzer"

say() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

say "Compilando (release)"
cargo build --release --quiet
echo "Listo: $BIN"

say "Los cinco casos de la demostración"
"$BIN" --demo

say "Un veredicto suelto"
"$BIN" "http://paypa1.com/login/verify"

say "La salida en JSON (para integrarlo con otro sistema)"
"$BIN" --json "http://paypa1.com/login/verify"

say "Fin de la demo"
