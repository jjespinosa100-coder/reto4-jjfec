#!/bin/bash
#===============================================================================
# TECHTRANSFER S.A.S. - techtransfer_recepcion.sh (Reto 4)
#
# Valida y descifra los paquetes que INNOVATECH deja en la carpeta de entrada
# del servidor SFTP. Puede procesar un paquete (-p) o toda la carpeta (-d).
#
#   1. Inspecciona el .tar antes de extraer (archivos regulares, nombres
#      exactos, sin rutas, tamano maximo)
#   2. Verifica la firma RSA-PSS del hash con la llave publica de INNOVATECH
#   3. Verifica el hash SHA-256 de los archivos cifrados
#   4. Rechaza paquetes repetidos (proteccion contra reenvio)
#   5. Recupera la clave de sesion con la llave privada RSA del proveedor,
#      descifra AES-256-CBC y decodifica Base64
#   Si algo falla, el paquete pasa a cuarentena y no se descifra.
#
# Uso:
#   techtransfer_recepcion.sh -d /sftp/innovatech/entrada
#   techtransfer_recepcion.sh -p /sftp/innovatech/entrada/<paquete>.tar
#   Opciones: -s pub_firma.pem -k priv_cifrado.pem -o salida -q cuarentena
#             -a archivo (paquetes aceptados) -m MB -c carpeta_control
#   Frase de paso de la llave privada, si tiene: variable PROVEEDOR_CLAVE_PASS
#
# Codigos: 0 ok | 1 uso | 3 no existe | 9 otra ejecucion | 11 tar invalido
#   12 firma | 13 hash | 14 reenvio | 15 descifrado | 16 uno o mas rechazados
#
# Curso: Algoritmos y Modelos Criptograficos (219027) - UNAD
#===============================================================================

set -uo pipefail
umask 077

PAQUETE=""; DIR_ENTRADA=""
CLAVE_PUB_FIRMA="/etc/techtransfer/claves/innovatech_firma_pub.pem"
CLAVE_PRIV_CIFRADO="/etc/techtransfer/claves/techtransfer_cifrado.pem"
DIR_SALIDA="/srv/techtransfer/recibidos"
DIR_CUARENTENA="/srv/techtransfer/cuarentena"
DIR_ARCHIVO="/srv/techtransfer/archivo"
DIR_CONTROL="/var/lib/techtransfer"
TAMANO_MAX_MB=2048
ITERACIONES_PBKDF2=100000

uso() {
    echo "Uso: $(basename "$0") (-p <paquete.tar> | -d <carpeta_entrada>) [-s pub_firma] [-k priv_cifrado] [-o salida] [-q cuarentena] [-m MB]" >&2
    exit 1
}

while getopts ":p:d:s:k:o:q:a:m:c:h" o; do
    case "$o" in
        p) PAQUETE="$OPTARG" ;; d) DIR_ENTRADA="$OPTARG" ;;
        s) CLAVE_PUB_FIRMA="$OPTARG" ;; k) CLAVE_PRIV_CIFRADO="$OPTARG" ;;
        o) DIR_SALIDA="$OPTARG" ;; q) DIR_CUARENTENA="$OPTARG" ;; a) DIR_ARCHIVO="$OPTARG" ;;
        m) TAMANO_MAX_MB="$OPTARG" ;; c) DIR_CONTROL="$OPTARG" ;;
        *) uso ;;
    esac
done
[[ -n "$PAQUETE" || -n "$DIR_ENTRADA" ]] || uso
[[ "$TAMANO_MAX_MB" =~ ^[0-9]+$ ]] || uso

mkdir -p "$DIR_CONTROL" 2>/dev/null || DIR_CONTROL="$HOME/.techtransfer"
mkdir -p "$DIR_CONTROL" "$DIR_SALIDA" "$DIR_CUARENTENA" "$DIR_ARCHIVO"
chmod 700 "$DIR_CONTROL"
LOG="$DIR_CONTROL/recepcion.log"
REGISTRO="$DIR_CONTROL/paquetes_procesados.txt"
touch "$REGISTRO"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] ${*:2}" | tee -a "$LOG" >&2; }

exec 9>>"$DIR_CONTROL/recepcion.lock"
flock -n 9 || { log "ERROR" "Ya hay otra verificacion en curso"; exit 9; }

for f in "$CLAVE_PUB_FIRMA" "$CLAVE_PRIV_CIFRADO"; do
    [[ -f "$f" ]] || { log "ERROR" "No se encuentra la llave: $f"; exit 3; }
done

RE='^(((PROY|INFO|CONT)-[0-9]{8}-[0-9]{8}))_[0-9]{8}_[0-9]{6}\.tar$'

#-------------------------------------------------------------------------------
# VERIFICACION DE UN PAQUETE (en un subproceso)
#-------------------------------------------------------------------------------
verificar() {
    set -e
    local PAQ="$1" ARCH NOMBRE TIPO HUELLA SALIDA ESPERADAS ENTRADAS TAM
    ARCH="$(basename "$PAQ")"
    T=""
    trap '[[ -n "$T" && -d "$T" ]] && { find "$T" -type f -exec shred -u -n 3 {} \; 2>/dev/null; rm -rf "$T"; }' EXIT
    rechazar() {
        log "ERROR" "[$ARCH] RECHAZADO: $1"
        mv -n "$PAQ" "$DIR_CUARENTENA/" 2>/dev/null || true
        log "ERROR" "[$ARCH] Enviado a cuarentena: $DIR_CUARENTENA/$ARCH"
        exit "${2:-20}"
    }

    [[ -f "$PAQ" && ! -L "$PAQ" ]] || { log "ERROR" "No existe el paquete: $PAQ"; exit 3; }
    [[ "$ARCH" =~ $RE ]] || rechazar "nombre de paquete fuera de la nomenclatura" 11
    NOMBRE="${BASH_REMATCH[2]}"; TIPO="${BASH_REMATCH[3]}"
    log "INFO" "===== Verificando $ARCH ====="

    # 1. Inspeccion del .tar antes de extraer
    ESPERADAS="$(printf '%s\n' "$NOMBRE.enc" "$NOMBRE.key.enc" "$NOMBRE.sha256" "$NOMBRE.sha256.sig" | sort)"
    ENTRADAS="$(tar -tf "$PAQ" 2>/dev/null | sort)" || rechazar "no es un archivo tar valido" 11
    [[ "$ENTRADAS" == "$ESPERADAS" ]] || rechazar "el paquete no trae exactamente los cuatro archivos esperados" 11
    tar --numeric-owner -tvf "$PAQ" | awk '$1 !~ /^-/ {exit 1}' \
        || rechazar "el paquete contiene enlaces, carpetas o dispositivos" 11
    TAM="$(tar --numeric-owner -tvf "$PAQ" | awk '{s+=$3} END{print s+0}')"
    (( TAM <= TAMANO_MAX_MB * 1024 * 1024 )) || rechazar "tamano excesivo ($TAM bytes)" 11
    T="$(mktemp -d "${TMPDIR:-/tmp}/techtransfer.XXXXXXXXXX")"
    timeout 300 tar -xf "$PAQ" -C "$T" -k --no-same-owner --no-same-permissions \
        || rechazar "no se pudo extraer el paquete" 11
    log "INFO" "[$ARCH] 1/5 Inspeccion del paquete superada (4 archivos regulares, $TAM bytes)"

    # 2. Firma digital del hash
    if ! openssl dgst -sha256 -verify "$CLAVE_PUB_FIRMA" \
            -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
            -signature "$T/$NOMBRE.sha256.sig" "$T/$NOMBRE.sha256" >/dev/null 2>&1; then
        rechazar "FIRMA INVALIDA: el hash no proviene de INNOVATECH o fue alterado" 12
    fi
    log "INFO" "[$ARCH] 2/5 Firma digital RSA-PSS valida: el emisor es INNOVATECH"

    # 3. Hash SHA-256 de los archivos cifrados
    [[ "$(awk '{print $2}' "$T/$NOMBRE.sha256" | sort | tr '\n' ' ')" == "$NOMBRE.enc $NOMBRE.key.enc " ]] \
        || rechazar "el manifiesto de hashes no corresponde al paquete" 13
    if ! ( cd "$T" && sha256sum -c --strict --quiet "$NOMBRE.sha256" ) >/dev/null 2>&1; then
        rechazar "HASH NO COINCIDE: los archivos cifrados fueron modificados" 13
    fi
    HUELLA="$(sha256sum "$T/$NOMBRE.sha256" | cut -d' ' -f1)"
    log "INFO" "[$ARCH] 3/5 Hash SHA-256 verificado en el destino: $(head -1 "$T/$NOMBRE.sha256" | cut -d' ' -f1)"

    # 4. Proteccion contra reenvio
    grep -qxF "$HUELLA" "$REGISTRO" && rechazar "este paquete ya fue procesado (posible reenvio)" 14
    log "INFO" "[$ARCH] 4/5 Paquete nuevo, no es un reenvio"

    # 5. Descifrado
    local PASSIN=()
    [[ -n "${PROVEEDOR_CLAVE_PASS:-}" ]] && PASSIN=(-passin env:PROVEEDOR_CLAVE_PASS)
    openssl pkeyutl -decrypt -inkey "$CLAVE_PRIV_CIFRADO" "${PASSIN[@]}" \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
        -in "$T/$NOMBRE.key.enc" -out "$T/clave_sesion" 2>/dev/null \
        || rechazar "no se pudo recuperar la clave de sesion" 15
    openssl enc -d -aes-256-cbc -pbkdf2 -iter "$ITERACIONES_PBKDF2" -md sha256 \
        -in "$T/$NOMBRE.enc" -out "$T/$NOMBRE.b64" -pass "file:$T/clave_sesion" 2>/dev/null \
        || rechazar "fallo el descifrado AES" 15
    shred -u -n 3 "$T/clave_sesion"

    mkdir -p "$DIR_SALIDA/$TIPO"
    SALIDA="$DIR_SALIDA/$TIPO/$NOMBRE.txt"
    [[ -e "$SALIDA" ]] && SALIDA="$DIR_SALIDA/$TIPO/${ARCH%.tar}.txt"
    base64 -d "$T/$NOMBRE.b64" > "$SALIDA" || rechazar "el contenido no es Base64 valido" 15

    echo "$HUELLA" >> "$REGISTRO"
    mv -n "$PAQ" "$DIR_ARCHIVO/" 2>/dev/null || rm -f "$PAQ"
    log "INFO" "[$ARCH] 5/5 Descifrado: $SALIDA (SHA-256 del documento $(sha256sum "$SALIDA" | cut -d' ' -f1))"
    log "INFO" "===== Paquete aceptado ====="
}

if [[ -n "$PAQUETE" ]]; then
    LISTA=("$PAQUETE")
else
    [[ -d "$DIR_ENTRADA" ]] || { log "ERROR" "No existe la carpeta: $DIR_ENTRADA"; exit 3; }
    mapfile -t LISTA < <(find "$DIR_ENTRADA" -maxdepth 1 -type f -name '*.tar' | sort)
    log "INFO" "Paquetes pendientes en $DIR_ENTRADA: ${#LISTA[@]} (los .part aun en transito se ignoran)"
fi

ACEPTADOS=0; RECHAZADOS=0; ULTIMO=0
for paq in "${LISTA[@]}"; do
    ( verificar "$paq" ); rc=$?
    if (( rc == 0 )); then ACEPTADOS=$((ACEPTADOS+1)); else ULTIMO=$rc; RECHAZADOS=$((RECHAZADOS+1)); fi
done
log "INFO" "Resumen: aceptados $ACEPTADOS | rechazados $RECHAZADOS"
if [[ -n "$PAQUETE" ]]; then exit "$ULTIMO"; fi
(( RECHAZADOS == 0 )) || exit 16
exit 0
