#!/bin/bash
#===============================================================================
# INNOVATECH SOLUTIONS S.A.S. - innovatech_envio.sh (Reto 4)
#
# Script unico y desatendido. Envia al servidor SFTP de TECHTRANSFER S.A.S.
# todo documento de /Transferencias/<proceso>/ que cumpla la nomenclatura
#     PROY|INFO|CONT-<8 digitos>-<DDMMAAAA>.txt   ej. PROY-00001234-23022026.txt
# sin modificar el codigo y sin pedir datos al usuario.
#
# Por cada archivo:
#   1. Codificacion Base64
#   2. Cifrado AES-256-CBC (PBKDF2) con una clave de sesion aleatoria; la clave
#      se cifra con la llave publica RSA-4096 del proveedor (OAEP-SHA256)
#   3. Hash SHA-256 de los archivos cifrados
#   4. Firma digital RSA-PSS del hash con la llave privada de INNOVATECH
#   5. Paquete .tar con los cuatro archivos
#   6. Envio por SFTP: llave Ed25519 y llave del servidor verificada
#   7. Descarga de lo subido, comparacion del hash y publicacion del paquete
#
# Uso:
#   innovatech_envio.sh -C /etc/innovatech/envio.conf             todos los tipos
#   innovatech_envio.sh -C /etc/innovatech/envio.conf -t PROY     un tipo
#   innovatech_envio.sh -C /etc/innovatech/envio.conf -f <archivo>
#
# Periodicidad (timers de systemd): PROY diaria, INFO semanal, CONT mensual.
#
# Codigos de salida: 0 todo enviado | 1 uso | 2 falta herramienta
#   5 configuracion invalida | 6 llaves o credenciales | 9 otra ejecucion activa
#   (por archivo, en el registro: 8 SFTP | 10 integridad en destino | 11 firma)
#   12 uno o mas archivos no se pudieron enviar
#
# Curso: Algoritmos y Modelos Criptograficos (219027) - UNAD
#===============================================================================

set -uo pipefail
umask 077

SFTP_HOST=""
SFTP_USUARIO="innovatech"
SFTP_PUERTO="22"
SFTP_RUTA="/entrada"
LLAVE_SSH="/etc/innovatech/claves/id_ed25519_sftp"
KNOWN_HOSTS="/etc/innovatech/known_hosts_techtransfer"
CLAVE_PUB_PROVEEDOR="/etc/innovatech/techtransfer_cifrado_pub.pem"
CLAVE_FIRMA="/etc/innovatech/claves/innovatech_firma.pem"
DIR_TRANSFERENCIAS="/Transferencias"
DIR_LOG="/var/log/innovatech"
TAMANO_MAX_MB=1024
ITERACIONES_PBKDF2=100000
CONFIG=""; TIPO=""; ARCHIVO_UNICO=""

uso() {
    echo "Uso: $(basename "$0") -C <config> [-t PROY|INFO|CONT] [-f <archivo>]" >&2
    exit 1
}

#-------------------------------------------------------------------------------
# PARAMETROS Y CONFIGURACION (lectura segura: no se ejecuta el archivo)
#-------------------------------------------------------------------------------
while getopts ":C:t:f:h" o; do
    case "$o" in
        C) CONFIG="$OPTARG" ;; t) TIPO="$OPTARG" ;; f) ARCHIVO_UNICO="$OPTARG" ;;
        *) uso ;;
    esac
done
[[ -z "$CONFIG" ]] && uso
[[ -n "$TIPO" && ! "$TIPO" =~ ^(PROY|INFO|CONT)$ ]] && { echo "Tipo invalido: $TIPO" >&2; exit 1; }
[[ -f "$CONFIG" ]] || { echo "No existe la configuracion: $CONFIG" >&2; exit 5; }

while IFS= read -r linea || [[ -n "$linea" ]]; do
    linea="${linea%%#*}"; linea="${linea//[$'\t\r ']/}"
    [[ -z "$linea" ]] && continue
    clave="${linea%%=*}"; valor="${linea#*=}"
    [[ "$valor" =~ [\$\`\;\|\&\<\>] ]] && { echo "Valor no permitido para $clave" >&2; exit 5; }
    case "$clave" in
        SFTP_HOST|SFTP_USUARIO|SFTP_PUERTO|SFTP_RUTA|LLAVE_SSH|KNOWN_HOSTS|CLAVE_PUB_PROVEEDOR|\
        CLAVE_FIRMA|DIR_TRANSFERENCIAS|DIR_LOG|TAMANO_MAX_MB) printf -v "$clave" '%s' "$valor" ;;
        *) echo "Clave desconocida en la configuracion: $clave" >&2; exit 5 ;;
    esac
done < "$CONFIG"

mkdir -p "$DIR_LOG" 2>/dev/null || DIR_LOG="$HOME/.innovatech"
mkdir -p "$DIR_LOG"
LOG="$DIR_LOG/envio.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] [$(id -un)] ${*:2}" | tee -a "$LOG" >&2; }

#-------------------------------------------------------------------------------
# UNA SOLA EJECUCION A LA VEZ
#-------------------------------------------------------------------------------
exec 9>>"$DIR_LOG/envio.lock"
flock -n 9 || { log "ERROR" "Ya hay otra ejecucion en curso"; exit 9; }

log "INFO" "===== Inicio de la ejecucion (tipo: ${TIPO:-todos}) ====="

#-------------------------------------------------------------------------------
# VALIDACIONES GENERALES
#-------------------------------------------------------------------------------
for h in openssl base64 sha256sum tar sftp ssh-keygen shred flock timeout stat; do
    command -v "$h" >/dev/null 2>&1 || { log "ERROR" "Falta la herramienta: $h"; exit 2; }
done
[[ "$SFTP_HOST" =~ ^[A-Za-z0-9.-]+$ ]]            || { log "ERROR" "SFTP_HOST invalido"; exit 5; }
[[ "$SFTP_USUARIO" =~ ^[a-z_][a-z0-9_-]*$ ]]      || { log "ERROR" "SFTP_USUARIO invalido"; exit 5; }
[[ "$SFTP_PUERTO" =~ ^[0-9]+$ && "$TAMANO_MAX_MB" =~ ^[0-9]+$ ]] || { log "ERROR" "Puerto o tamano invalidos"; exit 5; }
[[ "$SFTP_RUTA" =~ ^/?[A-Za-z0-9_][A-Za-z0-9/_.-]*$ && "$SFTP_RUTA" != *..* ]] || { log "ERROR" "SFTP_RUTA invalida"; exit 5; }
[[ -d "$DIR_TRANSFERENCIAS" ]]                    || { log "ERROR" "No existe $DIR_TRANSFERENCIAS"; exit 5; }

# Proteccion de credenciales: las llaves privadas deben existir, ser del
# usuario que ejecuta y no ser legibles por nadie mas.
for f in "$LLAVE_SSH" "$CLAVE_FIRMA"; do
    [[ -f "$f" && ! -L "$f" ]] || { log "ERROR" "No se encuentra la llave privada: $f"; exit 6; }
    perm="$(stat -c '%a' "$f")"; duenio="$(stat -c '%u' "$f")"
    if [[ "$duenio" != "$(id -u)" || ! "$perm" =~ ^[46]00$ ]]; then
        log "ERROR" "Llave privada mal protegida ($f, permisos $perm). Debe ser 600 o 400 y del usuario $(id -un)"; exit 6
    fi
done
# Anclas de confianza (llave del servidor y llave publica del proveedor):
# nadie distinto del dueno puede reemplazarlas.
for f in "$KNOWN_HOSTS" "$CLAVE_PUB_PROVEEDOR"; do
    [[ -f "$f" ]] || { log "ERROR" "No se encuentra: $f"; exit 6; }
    perm="$(stat -c '%a' "$f")"
    (( (8#$perm & 8#022) == 0 )) || { log "ERROR" "$f puede ser modificado por otros usuarios (permisos $perm)"; exit 6; }
done
PERM_CONF="$(stat -c '%a' "$CONFIG")"
(( (8#$PERM_CONF & 8#022) == 0 )) || { log "ERROR" "La configuracion puede ser modificada por otros usuarios (permisos $PERM_CONF)"; exit 6; }
log "INFO" "Credenciales protegidas: llaves privadas con permisos $(stat -c '%a' "$LLAVE_SSH")/$(stat -c '%a' "$CLAVE_FIRMA") y sin contrasenas en el script"

BITS=$(openssl pkey -pubin -in "$CLAVE_PUB_PROVEEDOR" -noout -text 2>/dev/null | grep -oE '[0-9]+ bit' | head -1 | cut -d' ' -f1)
[[ -n "$BITS" ]] && (( BITS >= 3072 )) || { log "ERROR" "La llave publica del proveedor no es RSA de al menos 3072 bits"; exit 6; }

HUELLA_SERVIDOR="$(ssh-keygen -lf "$KNOWN_HOSTS" 2>/dev/null | awk 'NR==1{print $2}')"
[[ -n "$HUELLA_SERVIDOR" ]] || { log "ERROR" "known_hosts sin una llave de servidor valida"; exit 6; }
log "INFO" "Llave del servidor SFTP fijada: $HUELLA_SERVIDOR (se rechaza cualquier otra)"

# shellcheck disable=SC2054
OPC_SSH=(
    -P "$SFTP_PUERTO" -i "$LLAVE_SSH"
    -o IdentitiesOnly=yes -o BatchMode=yes
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN_HOSTS"
    -o HostKeyAlgorithms=ssh-ed25519
    -o KexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org
    -o Ciphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
    -o PasswordAuthentication=no -o ConnectTimeout=20
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3
)
DESTINO="${SFTP_USUARIO}@${SFTP_HOST}"
RUTA="${SFTP_RUTA%/}"
RE_NOMBRE='^(PROY|INFO|CONT)-[0-9]{8}-([0-9]{2})([0-9]{2})([0-9]{4})\.txt$'

#-------------------------------------------------------------------------------
# PROCESAMIENTO DE UN ARCHIVO (en un subproceso: un fallo no detiene a los demas)
#-------------------------------------------------------------------------------
procesar() {
    set -e
    local ARCHIVO="$1" NOMBRE_ARCHIVO NOMBRE MARCA PAQUETE HASH_LOCAL HASH_REMOTO
    NOMBRE_ARCHIVO="$(basename "$ARCHIVO")"; NOMBRE="${NOMBRE_ARCHIVO%.txt}"
    T="$(mktemp -d "${TMPDIR:-/tmp}/innovatech.XXXXXXXXXX")"  # global en el subproceso: la usa la trampa EXIT
    trap 'find "$T" -type f -exec shred -u -n 3 {} \; 2>/dev/null; rm -rf "$T"' EXIT
    fallo() { log "ERROR" "[$NOMBRE_ARCHIVO] $1"; exit "${2:-20}"; }

    MARCA="$(date '+%Y%m%d_%H%M%S')"
    PAQUETE="${NOMBRE}_${MARCA}.tar"
    log "INFO" "[$NOMBRE_ARCHIVO] Procesando ($(stat -c%s "$ARCHIVO") bytes)"

    # 1. Base64
    base64 "$ARCHIVO" > "$T/$NOMBRE.b64" || fallo "Fallo la codificacion Base64"
    log "INFO" "[$NOMBRE_ARCHIVO] 1/7 Codificado en Base64"

    # 2. Cifrado hibrido
    openssl rand -base64 48 > "$T/clave_sesion" || fallo "No se pudo generar la clave de sesion"
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$ITERACIONES_PBKDF2" -md sha256 \
        -in "$T/$NOMBRE.b64" -out "$T/$NOMBRE.enc" -pass "file:$T/clave_sesion" \
        || fallo "Fallo el cifrado AES"
    openssl pkeyutl -encrypt -pubin -inkey "$CLAVE_PUB_PROVEEDOR" \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
        -in "$T/clave_sesion" -out "$T/$NOMBRE.key.enc" || fallo "Fallo el cifrado RSA-OAEP de la clave"
    shred -u -n 3 "$T/clave_sesion" "$T/$NOMBRE.b64"
    log "INFO" "[$NOMBRE_ARCHIVO] 2/7 Cifrado AES-256-CBC; clave de sesion protegida con RSA-$BITS OAEP"

    # 3. Hash SHA-256
    ( cd "$T" && sha256sum "$NOMBRE.enc" "$NOMBRE.key.enc" > "$NOMBRE.sha256" ) || fallo "Fallo el calculo del hash"
    log "INFO" "[$NOMBRE_ARCHIVO] 3/7 SHA-256 del cifrado: $(cut -d' ' -f1 "$T/$NOMBRE.sha256" | head -1)"

    # 4. Firma digital
    local PASSIN=()
    [[ -n "${INNOVATECH_FIRMA_PASS:-}" ]] && PASSIN=(-passin env:INNOVATECH_FIRMA_PASS)
    openssl dgst -sha256 -sign "$CLAVE_FIRMA" "${PASSIN[@]}" \
        -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
        -out "$T/$NOMBRE.sha256.sig" "$T/$NOMBRE.sha256" </dev/null 2>/dev/null \
        || fallo "No se pudo firmar: revise la llave de firma o INNOVATECH_FIRMA_PASS" 11
    log "INFO" "[$NOMBRE_ARCHIVO] 4/7 Hash firmado con RSA-PSS"

    # 5. Paquete
    tar -cf "$T/$PAQUETE" -C "$T" --owner=0 --group=0 --numeric-owner \
        "$NOMBRE.enc" "$NOMBRE.key.enc" "$NOMBRE.sha256" "$NOMBRE.sha256.sig" || fallo "Fallo el empaquetado"
    HASH_LOCAL="$(sha256sum "$T/$PAQUETE" | cut -d' ' -f1)"
    log "INFO" "[$NOMBRE_ARCHIVO] 5/7 Paquete $PAQUETE (SHA-256 $HASH_LOCAL)"

    # 6. Envio por SFTP con extension .part
    printf 'put "%s" "%s"\nget "%s" "%s"\n' "$T/$PAQUETE" "$RUTA/$PAQUETE.part" \
        "$RUTA/$PAQUETE.part" "$T/verificacion.tar" > "$T/lote1"
    if ! timeout 1800 sftp "${OPC_SSH[@]}" -b "$T/lote1" "$DESTINO" >/dev/null 2>"$T/sftp.err"; then
        if grep -qE 'IDENTIFICATION HAS CHANGED|Host key verification failed' "$T/sftp.err"; then
            fallo "SERVIDOR NO CONFIABLE: su llave no coincide con la fijada ($HUELLA_SERVIDOR). Posible suplantacion; no se envio nada" 8
        fi
        fallo "Fallo la conexion o la transferencia SFTP: $(grep -v '^@' "$T/sftp.err" | tr '\n' ' ' | cut -c1-200)" 8
    fi
    log "INFO" "[$NOMBRE_ARCHIVO] 6/7 Enviado a $DESTINO:$RUTA (servidor verificado $HUELLA_SERVIDOR)"

    # 7. Verificacion del hash de lo que quedo en el destino
    HASH_REMOTO="$(sha256sum "$T/verificacion.tar" | cut -d' ' -f1)"
    if [[ "$HASH_LOCAL" != "$HASH_REMOTO" ]]; then
        printf 'rm "%s"\n' "$RUTA/$PAQUETE.part" > "$T/lote2"
        timeout 120 sftp "${OPC_SSH[@]}" -b "$T/lote2" "$DESTINO" >/dev/null 2>&1 || true
        fallo "FALLO DE INTEGRIDAD: origen $HASH_LOCAL destino $HASH_REMOTO" 10
    fi
    printf 'rename "%s" "%s"\n' "$RUTA/$PAQUETE.part" "$RUTA/$PAQUETE" > "$T/lote2"
    timeout 120 sftp "${OPC_SSH[@]}" -b "$T/lote2" "$DESTINO" >/dev/null 2>&1 \
        || fallo "No se pudo publicar el paquete" 8
    log "INFO" "[$NOMBRE_ARCHIVO] 7/7 INTEGRIDAD VERIFICADA EN EL DESTINO: origen $HASH_LOCAL = destino $HASH_REMOTO"
}

#-------------------------------------------------------------------------------
# SELECCION DE ARCHIVOS
#-------------------------------------------------------------------------------
if [[ -n "$ARCHIVO_UNICO" ]]; then
    CANDIDATOS=("$ARCHIVO_UNICO")
else
    mapfile -t CANDIDATOS < <(find "$DIR_TRANSFERENCIAS" -mindepth 2 -maxdepth 2 -type f | sort)
fi

# Mueve un archivo a una subcarpeta sin sobrescribir otro con el mismo nombre
apartar() {
    local destino; destino="$2/$(basename "$1")"
    mkdir -p "$2"
    [[ -e "$destino" ]] && destino="$2/$(basename "$1" .txt)_$(date +%Y%m%d%H%M%S).txt"
    mv "$1" "$destino"
}

ENVIADOS=0; FALLIDOS=0; IGNORADOS=0; RECHAZADOS=0
for f in "${CANDIDATOS[@]}"; do
    [[ -f "$f" && ! -L "$f" ]] || { log "WARN" "No es un archivo regular, se ignora: $f"; IGNORADOS=$((IGNORADOS+1)); continue; }
    n="$(basename "$f")"
    if [[ ! "$n" =~ $RE_NOMBRE ]]; then
        log "WARN" "Fuera de la nomenclatura, no se envia: $f"; IGNORADOS=$((IGNORADOS+1)); continue
    fi
    [[ -n "$TIPO" && "${BASH_REMATCH[1]}" != "$TIPO" ]] && continue
    dir="$(dirname "$f")"
    fecha="${BASH_REMATCH[4]}-${BASH_REMATCH[3]}-${BASH_REMATCH[2]}"
    if ! date -d "$fecha" >/dev/null 2>&1 || [[ "$(date -d "$fecha" +%Y-%m-%d 2>/dev/null)" != "$fecha" ]]; then
        apartar "$f" "$dir/rechazados"
        log "WARN" "Fecha invalida en el nombre, movido a rechazados: $n"; RECHAZADOS=$((RECHAZADOS+1)); continue
    fi
    if (( $(stat -c%s "$f") > TAMANO_MAX_MB * 1024 * 1024 )); then
        apartar "$f" "$dir/rechazados"
        log "WARN" "Supera $TAMANO_MAX_MB MB, movido a rechazados: $n"; RECHAZADOS=$((RECHAZADOS+1)); continue
    fi
    ( procesar "$f" ); rc=$?
    if (( rc == 0 )); then
        apartar "$f" "$dir/enviados"; ENVIADOS=$((ENVIADOS+1))
    else
        FALLIDOS=$((FALLIDOS+1))
        log "ERROR" "[$n] No se envio (codigo $rc); queda en su carpeta y se reintenta en la proxima ejecucion"
    fi
done

log "INFO" "===== Resumen: enviados $ENVIADOS | fallidos $FALLIDOS | rechazados $RECHAZADOS | ignorados $IGNORADOS ====="
(( FALLIDOS == 0 )) || exit 12
exit 0
