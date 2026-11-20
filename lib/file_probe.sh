#!/usr/bin/env bash
# Cross-check libmagic with an independent, offline signature dataset.
# The dataset and its MIT license live in data/. No network requests or eval.
set -u
set -o pipefail
export LC_ALL=C

fail() { printf 'Error: %s\n' "$*" >&2; exit 2; }
usage() {
    cat <<EOF
Uso: ${0##*/} [-v|--verbose] [--max-bytes N] [--] ARCHIVO

Contrasta SIEMPRE el MIME de file/libmagic con una base independiente de
magic numbers. Comprueba offsets y comodines; no confía en el nombre.
Analiza también el texto y posibles fragmentos de código incrustados.

  -v, --verbose  Muestra todas las coincidencias y los primeros 32 bytes.
  -h, --help     Muestra esta ayuda.
  --max-bytes N  Límite de muestra para contenido (predeterminado: 1048576).
  --version     Muestra la versión.
  --            Permite nombres que empiezan por '-'.

Ejemplos:
  ./${0##*/} "imagen.php"
  ./${0##*/} --verbose "archivo con espacios.bin"
  ./${0##*/} -- -archivo

Códigos: 0 = MIME y firma compatibles; 1 = evidencia parcial o desconocido;
         2 = error de uso/lectura/base; 3 = contradicción o ambigüedad.
El código 0 NO garantiza integridad, validez completa ni seguridad.
Conserva data/ y lib/ junto al script. Requiere Bash >= 4.4 y Python >= 3.9.
EOF
}

(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )) || fail 'Se requiere Bash 4.4 o superior.'
verbose=false
content_limit=1048576
while (( $# )); do
    case "$1" in
        -v|--verbose) verbose=true; shift ;;
        -h|--help) usage; exit 0 ;;
        --version) printf 'file_magic_number 3.0.0\n'; exit 0 ;;
        --max-bytes)
            (( $# >= 2 )) || fail 'Falta N después de --max-bytes.'
            [[ "$2" =~ ^[0-9]{1,8}$ ]] || fail '--max-bytes requiere un número decimal.'
            content_limit=$((10#$2))
            (( content_limit >= 4096 && content_limit <= 16777216 )) || fail '--max-bytes debe estar entre 4096 y 16777216.'
            shift 2 ;;
        --) shift; break ;;
        -*) fail "Opción desconocida: $1. Usa -- antes de un nombre con guion." ;;
        *) break ;;
    esac
done
if (( $# != 1 )); then usage >&2; exit 2; fi

for dependency in file od tr stat readlink dirname python3 timeout; do
    command -v "$dependency" >/dev/null 2>&1 || fail "Falta '$dependency' (instala file, coreutils y Python 3)."
done
script_path=$(readlink -f -- "${BASH_SOURCE[0]}") || fail 'No se pudo resolver la ruta del script.'
script_dir=$(dirname -- "$script_path")
# Internal probe normally lives in lib/. Isolated regression copies can live
# beside their own data/ and lib/ directories.
if [[ "${script_dir##*/}" == lib ]]; then script_dir=$(dirname -- "$script_dir"); fi
database="$script_dir/data/signatures.tsv"
[[ -r "$database" ]] || fail 'Falta data/signatures.tsv. Descarga o clona el repositorio completo.'
content_helper="$script_dir/lib/content_probe.py"
[[ -r "$content_helper" ]] || fail 'Falta lib/content_probe.py. Descarga o actualiza el repositorio completo.'

path=$1
[[ "$path" == /* ]] || path="./$path"
[[ -f "$path" ]] || fail 'La ruta no es un archivo regular accesible.'
[[ -r "$path" ]] || fail 'No tienes permiso para leer el archivo.'
size=$(stat -Lc '%s' -- "$path") || fail 'No se pudo consultar el tamaño.'
[[ "$size" =~ ^[0-9]+$ ]] || fail 'Tamaño de archivo no válido.'

# Read the header even when MIME recognition succeeds. Hex avoids Bash NUL loss.
header=$(od -An -v -tx1 -N 4096 -- "$path" | tr -d '[:space:]') || fail 'No se pudo leer la cabecera.'
mime=$(file -b -L -E --mime-type -- "$path") || fail 'No se pudo detectar el MIME.'
description=$(file -b -L -E -- "$path") || fail 'No se pudo obtener la descripción de file.'

declare -A found patterns observed offsets ids extnames expected labels minimum strength
declare -a order=()
rules=0
while IFS=$'\t' read -r id family offset pattern extensions mimes label min_size extra; do
    [[ -z "$id" || "$id" == \#* ]] && continue
    # Treat the database as data. Validate before arithmetic or glob matching.
    [[ "$id" =~ ^S[0-9]+$ && "$family" =~ ^[a-z0-9][a-z0-9_-]*$ &&
       "$offset" =~ ^-?[0-9]{1,8}$ && "$min_size" =~ ^[0-9]{1,8}$ &&
       "$pattern" =~ ^([0-9a-f]{2}|\?\?)+$ && -z "$extra" &&
       -n "$extensions" && -n "$mimes" && -n "$label" ]] || fail "Regla de firmas inválida: $id"
    (( ${#pattern} <= 4096 )) || fail "Firma demasiado larga: $id"
    ((rules += 1))
    # Decimal normalization avoids interpreting a leading zero as octal.
    if [[ "$offset" == -* ]]; then
        position=$((size - 10#${offset#-}))
    else
        position=$((10#$offset))
    fi
    length=$((${#pattern} / 2))
    (( position >= 0 && position + length <= size )) || continue
    if (( position + length <= ${#header} / 2 )); then
        actual=${header:position*2:length*2}
    else
        actual=$(od -An -v -tx1 -j "$position" -N "$length" -- "$path" | tr -d '[:space:]') ||
            fail "No se pudo comprobar el offset $position."
    fi
    # The unquoted RHS is intentionally a validated hex glob ('??' = one byte).
    [[ "$actual" == $pattern ]] || continue
    fixed=${pattern//\?/}
    score=$((${#fixed} / 2))
    if [[ -z "${found[$family]:-}" ]]; then
        order+=("$family")
    elif (( score <= strength[$family] )); then
        continue
    fi
    found[$family]=1
    patterns[$family]=$pattern
    observed[$family]=$actual
    offsets[$family]=$position
    ids[$family]=$id
    extnames[$family]=$extensions
    expected[$family]=$mimes
    labels[$family]=$label
    minimum[$family]=$((10#$min_size))
    strength[$family]=$score
done < "$database"
(( rules >= 1 )) || fail 'La base de firmas está vacía.'

# Suppress only documented parent signatures, never an unrelated candidate.
[[ -n "${found[cr2]:-}" ]] && unset 'found[tif]'
[[ -n "${found[eps]:-}" ]] && unset 'found[ps]'

declare -a strong=() weak=()
for family in "${order[@]}"; do
    [[ -n "${found[$family]:-}" ]] || continue
    # Short signatures are useful clues, but must not produce a unique verdict.
    if (( strength[$family] >= 4 )); then strong+=("$family"); else weak+=("$family"); fi
done

status=1
verdict='DESCONOCIDO: sin una firma corroborante en esta base.'
type_label=$description
selected=''
short_signature=false
if (( ${#strong[@]} > 1 )); then
    verdict='AMBIGUO: coinciden firmas de varias familias; no se elige una a ciegas.'
    type_label='varios formatos candidatos'
    status=3
elif (( ${#strong[@]} == 1 )); then
    selected=${strong[0]}
elif (( ${#weak[@]} == 1 )); then
    selected=${weak[0]}
    short_signature=true
elif (( ${#weak[@]} > 1 )); then
    verdict='EVIDENCIA PARCIAL: solo hay firmas cortas o poco específicas.'
    type_label='firmas débiles; consulta también el MIME'
elif [[ "$mime" == text/* || "$mime" == application/json || "$mime" == application/xml ]]; then
    verdict='SOLO MIME: contenido textual sin firma propia corroborante en esta base.'
elif [[ "$mime" != application/octet-stream && "$mime" != inode/x-empty && "$mime" != application/x-empty ]]; then
    verdict='SOLO MIME: libmagic propone un formato; la base independiente no lo corrobora.'
fi

if [[ -n "$selected" ]]; then
    type_label=${labels[$selected]}
    if (( size < minimum[$selected] )); then
        verdict='EVIDENCIA PARCIAL: firma presente, pero tamaño insuficiente para esta familia.'
    elif [[ "$short_signature" == true ]]; then
        verdict='EVIDENCIA PARCIAL: firma corta; incluso si coincide el MIME, no basta para un veredicto firme.'
    elif [[ "$selected" == cafebabe ]]; then
        verdict='AMBIGUO: Java class y Mach-O universal comparten esta firma.'
        status=3
    elif [[ ",${expected[$selected]}," == *",$mime,"* && "$mime" != application/octet-stream ]]; then
        verdict='CONCORDANTE: el MIME y los magic numbers son compatibles.'
        status=0
        case "$selected" in
            zip|ole|ebml|bmff|ar) verdict='CONCORDANTE EN FAMILIA: el MIME es compatible con el contenedor; la firma no distingue su subtipo.' ;;
        esac
    elif [[ "${expected[$selected]}" == '-' || "$mime" == application/octet-stream ]]; then
        verdict='EVIDENCIA PARCIAL: firma reconocida, sin corroboración MIME de esta familia.'
    else
        verdict='CONTRADICCIÓN: el MIME y la firma apuntan a tipos no compatibles en la tabla.'
        status=3
    fi
fi

# Extra sanity checks for a few common formats. These detect obvious truncation,
# but are deliberately NOT called full validation (no full decoding or CRC pass).
sanity='no implementada para esta familia'
if [[ -n "$selected" ]]; then
    case "$selected" in
        png)
            tail_hex=''
            if (( size >= 12 )); then
                tail_hex=$(od -An -v -tx1 -j "$((size - 12))" -N 12 -- "$path" | tr -d '[:space:]') || fail 'No se pudo leer el cierre PNG.'
            fi
            if [[ "${header:16:16}" != 0000000d49484452 || "$tail_hex" != 0000000049454e44ae426082 ]]; then
                sanity='falló: se esperaba IHDR inicial e IEND final de PNG'
            else
                sanity='pasó: IHDR inicial e IEND final; no se verificaron todos los bloques/CRC'
            fi ;;
        jpg)
            tail_hex=''
            if (( size >= 2 )); then
                tail_hex=$(od -An -v -tx1 -j "$((size - 2))" -N 2 -- "$path" | tr -d '[:space:]') || fail 'No se pudo leer el cierre JPEG.'
            fi
            if [[ "$tail_hex" == ffd9 ]]; then sanity='pasó: cierre JPEG EOI; no se decodificó la imagen'
            else sanity='falló: no hay cierre JPEG EOI al final (puede estar truncado o tener datos añadidos)'; fi ;;
    esac
fi
if [[ "$sanity" == falló:* ]]; then
    if (( status != 3 )); then
        verdict='EVIDENCIA PARCIAL: la comprobación básica de estructura falló.'
        status=1
    fi
fi

# The textual layer supplements binary evidence; it must never replace an image,
# container or executable with the language of one of its strings.
binary_container=0
if [[ -n "$selected" ]]; then
    case "$selected" in xml|svg|rtf|eml|srt) ;; *) binary_container=1 ;; esac
elif [[ "$mime" == image/* || "$mime" == audio/* || "$mime" == video/* || "$mime" == application/pdf || "$mime" == application/zip ]]; then
    [[ "$mime" == image/svg+xml ]] || binary_container=1
fi
content_report=$(timeout --signal=TERM --kill-after=1s 8s python3 -I "$content_helper" \
    --max-bytes "$content_limit" --binary-container "$binary_container" -- "$path") ||
    fail 'No se pudo completar el análisis de contenido dentro de sus límites.'
content_kind=''
content_primary='-'
content_encoding=''
sampled_bytes=0
content_total=0
content_alert=0
content_ambiguous=0
declare -a content_lines=() content_notes=()
while IFS=$'\t' read -r field a b c d e f; do
    case "$field" in
        META) content_kind=$a; content_encoding=$b; sampled_bytes=$c; content_total=$d ;;
        PRIMARY) content_primary=$a ;;
        ALERT) content_alert=$a; content_ambiguous=$b ;;
        FINDING) content_lines+=("Contenido: $b | $c | $d | byte $e | $f") ;;
        NOTE) content_notes+=("Nota de contenido: $a") ;;
        *) fail 'Respuesta no reconocida del analizador de contenido.' ;;
    esac
done <<< "$content_report"
[[ -n "$content_kind" ]] || fail 'El analizador de contenido no devolvió su informe.'
if [[ "$content_kind" == texto && "$binary_container" == 0 && "$content_primary" != '-' ]]; then
    if (( status != 3 )); then
        type_label=$content_primary
        if [[ -z "$selected" ]]; then
            status=1
            verdict='CONTENIDO PROBABLE: clasificación por texto/sintaxis; sin firma binaria única corroborante.'
        fi
    fi
fi
if [[ "$content_alert" == 1 || "$content_ambiguous" == 1 ]]; then
    if (( status != 3 )); then
        verdict='REVISAR CONTENIDO: posibles fragmentos incrustados o lenguajes ambiguos; consulta las evidencias.'
        status=3
    fi
fi
if (( size == 0 )); then type_label='archivo vacío'; verdict='SIN EVIDENCIA: no hay bytes para identificar un formato.'; fi
printf 'Tipo orientativo: %s\n' "$type_label"
if [[ -n "$selected" ]]; then printf 'Extensiones de la familia: %s\n' "${extnames[$selected]}"; fi
printf 'MIME detectado: %s\n' "$mime"
printf 'Resultado: %s\n' "$verdict"
printf 'Estructura básica: %s\n' "$sanity"

count=0
for family in "${strong[@]}" "${weak[@]}"; do
    ((count += 1))
    if [[ "$verbose" == true ]] || ((count <= 8)); then
        printf 'Magic [%s]: %s | byte %s | patrón %s | observado %s\n' \
            "${ids[$family]}" "${labels[$family]}" "${offsets[$family]}" "${patterns[$family]}" "${observed[$family]}"
    fi
done
(( count > 0 )) || printf 'Magic: sin coincidencias entre las %s reglas de la base.\n' "$rules"
if (( count > 8 )) && [[ "$verbose" == false ]]; then printf 'Hay %s coincidencias; usa --verbose para verlas todas.\n' "$count"; fi

printf 'Muestra de contenido: %s/%s bytes | codificación: %s\n' "$sampled_bytes" "$content_total" "$content_encoding"
for content_line in "${content_lines[@]}" "${content_notes[@]}"; do printf '%s\n' "$content_line"; done
printf 'Alcance: identifica tipos probables; no garantiza validez completa ni seguridad.\n'
if [[ "$verbose" == true ]]; then
    printf 'Descripción de file: %s\n' "$description"
    printf 'Tamaño: %s bytes | reglas consultadas: %s\n' "$size" "$rules"
    printf 'Base: TheDiscordian/magic-bytes (copia local con licencia MIT).\n'
    printf 'Primeros 32 bytes (hex): %s\n' "${header:0:64}"
fi
exit "$status"
