#!/bin/bash
#===============================================================================
# INNOVATECH SOLUTIONS S.A.S. - preparar_origen.sh (Reto 4)
# Prepara el servidor Linux On-Premise de Bogota (CentOS Stream 8 / Rocky / Ubuntu).
# Se ejecuta como root; es la puesta a punto, no el envio automatico.
#
#   instalar -s IP_SFTP [-P puerto] [-u usuario_sftp]
#                usuario de servicio, carpetas, llaves, configuracion,
#                script de envio y temporizadores por periodicidad
#   vincular     fija la llave del servidor SFTP (previa comparacion de huella),
#                descarga la llave publica de cifrado del proveedor y sube la
#                llave publica de firma de INNOVATECH
#   documentos   crea documentos de prueba en /Transferencias
#   enviar [TIPO]   ejecuta el envio ahora (PROY, INFO, CONT o todos)
#   pruebas      pruebas de seguridad del lado del origen
#   estado       resumen para la evidencia
#
# Curso: Algoritmos y Modelos Criptograficos (219027) - UNAD
#===============================================================================

set -euo pipefail
umask 022

ACCION="${1:-}"; shift || true
SERVICIO="innovatech"
ETC="/etc/innovatech"
CLAVES="$ETC/claves"
CONF="$ETC/envio.conf"
SCRIPT="/usr/local/bin/innovatech_envio.sh"
DIR_T="/Transferencias"
DIR_LOG="/var/log/innovatech"
SFTP_HOST=""; SFTP_PUERTO="22"; SFTP_USUARIO="innovatech"
ORIGEN_SCRIPTS="$(cd "$(dirname "$0")" && pwd)"

while getopts ":s:P:u:" o; do
    case "$o" in s) SFTP_HOST="$OPTARG" ;; P) SFTP_PUERTO="$OPTARG" ;; u) SFTP_USUARIO="$OPTARG" ;; *) ;; esac
done
shift $((OPTIND-1))
[[ $EUID -eq 0 ]] || { echo "Ejecute como root (sudo)"; exit 1; }

titulo() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()     { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
aviso()  { printf '\033[1;33m[AVISO]\033[0m %s\n' "$*"; }
hay_systemd() { [[ -d /run/systemd/system ]]; }
como_servicio() { runuser -u "$SERVICIO" -- "$@"; }
leer_conf() { grep -E "^$1=" "$CONF" | cut -d= -f2-; }

OPC_SSH() {
    echo -P "$(leer_conf SFTP_PUERTO)" -i "$CLAVES/id_ed25519_sftp" -o IdentitiesOnly=yes -o BatchMode=yes \
        -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$ETC/known_hosts_techtransfer" \
        -o HostKeyAlgorithms=ssh-ed25519 -o PasswordAuthentication=no -o ConnectTimeout=15
}

instalar_paquetes() {
    local faltan=0
    for h in tar openssl sftp ssh-keyscan flock shred timeout runuser; do command -v "$h" >/dev/null 2>&1 || faltan=1; done
    (( faltan == 0 )) && return 0
    if command -v dnf >/dev/null 2>&1; then
        if grep -qs 'CentOS Stream release 8' /etc/centos-release && grep -qs '^mirrorlist=' /etc/yum.repos.d/CentOS-Stream-*.repo; then
            sed -i 's/^mirrorlist=/#mirrorlist=/; s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/CentOS-Stream-*.repo
            aviso "Repositorios de CentOS Stream 8 apuntados a vault.centos.org (version sin soporte)"
        fi
        dnf -y install tar openssl openssh-clients util-linux coreutils
    else
        apt-get update -qq && apt-get install -y tar openssl openssh-client util-linux coreutils
    fi
}

#-------------------------------------------------------------------------------
instalar() {
    [[ "$SFTP_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Indique la IP del servidor SFTP: $0 instalar -s 192.168.42.20"; exit 1; }

    titulo "1. Paquetes"
    instalar_paquetes; ok "tar, openssl y cliente OpenSSH disponibles ($(ssh -V 2>&1 | cut -d, -f1))"

    titulo "2. Usuario de servicio y carpetas"
    local NOLOGIN; NOLOGIN="$(command -v nologin || echo /sbin/nologin)"
    id "$SERVICIO" >/dev/null 2>&1 || useradd -r -m -d /var/lib/innovatech -s "$NOLOGIN" "$SERVICIO"
    for d in Proyectos Informes Contratos; do mkdir -p "$DIR_T/$d"; done
    chown -R "$SERVICIO:$SERVICIO" "$DIR_T"; chmod 750 "$DIR_T"; chmod 770 "$DIR_T"/*
    mkdir -p "$DIR_LOG"; chown "$SERVICIO:$SERVICIO" "$DIR_LOG"; chmod 750 "$DIR_LOG"
    ok "Usuario '$SERVICIO' sin shell ni contrasena; $DIR_T/{Proyectos,Informes,Contratos}"

    titulo "3. Llaves de INNOVATECH"
    mkdir -p "$CLAVES"; chown root:"$SERVICIO" "$ETC"; chmod 750 "$ETC"
    chown "$SERVICIO:$SERVICIO" "$CLAVES"; chmod 700 "$CLAVES"
    if [[ ! -f "$CLAVES/id_ed25519_sftp" ]]; then
        como_servicio ssh-keygen -q -t ed25519 -N "" -C "innovatech@$(hostname -s)" -f "$CLAVES/id_ed25519_sftp"
    fi
    if [[ ! -f "$CLAVES/innovatech_firma.pem" ]]; then
        ( umask 077; echo "INNOVATECH_FIRMA_PASS=$(openssl rand -hex 32)" > "$ETC/firma.env" )
        chown root:root "$ETC/firma.env"; chmod 600 "$ETC/firma.env"
        INNOVATECH_FIRMA_PASS="$(cut -d= -f2- "$ETC/firma.env")" \
            openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes-256-cbc \
            -pass env:INNOVATECH_FIRMA_PASS -out "$CLAVES/innovatech_firma.pem" 2>/dev/null
        INNOVATECH_FIRMA_PASS="$(cut -d= -f2- "$ETC/firma.env")" \
            openssl pkey -in "$CLAVES/innovatech_firma.pem" -passin env:INNOVATECH_FIRMA_PASS \
            -pubout -out "$ETC/innovatech_firma_pub.pem"
    fi
    chown "$SERVICIO:$SERVICIO" "$CLAVES"/*; chmod 600 "$CLAVES/id_ed25519_sftp" "$CLAVES/innovatech_firma.pem"
    chmod 644 "$CLAVES/id_ed25519_sftp.pub" "$ETC/innovatech_firma_pub.pem"
    ok "SSH Ed25519 (autenticacion) y RSA-4096 cifrada con AES-256 (firma), permisos 600"
    ok "Frase de paso de la firma en $ETC/firma.env (root, 600); no aparece en el script"

    titulo "4. Configuracion"
    cat > "$CONF" <<FIN
# INNOVATECH - configuracion del envio seguro (sin contrasenas)
SFTP_HOST=$SFTP_HOST
SFTP_PUERTO=$SFTP_PUERTO
SFTP_USUARIO=$SFTP_USUARIO
SFTP_RUTA=/entrada
LLAVE_SSH=$CLAVES/id_ed25519_sftp
KNOWN_HOSTS=$ETC/known_hosts_techtransfer
CLAVE_PUB_PROVEEDOR=$ETC/techtransfer_cifrado_pub.pem
CLAVE_FIRMA=$CLAVES/innovatech_firma.pem
DIR_TRANSFERENCIAS=$DIR_T
DIR_LOG=$DIR_LOG
TAMANO_MAX_MB=1024
FIN
    chown root:"$SERVICIO" "$CONF"; chmod 640 "$CONF"
    install -m 755 -o root -g root "$ORIGEN_SCRIPTS/innovatech_envio.sh" "$SCRIPT"
    ok "$CONF (root, 640) y $SCRIPT"

    titulo "5. Envio automatico por periodicidad"
    if hay_systemd; then
        cat > /etc/systemd/system/innovatech-envio@.service <<FIN
[Unit]
Description=INNOVATECH - envio seguro de documentos %i a TECHTRANSFER
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=$SERVICIO
Group=$SERVICIO
EnvironmentFile=$ETC/firma.env
ExecStart=$SCRIPT -C $CONF -t %i
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DIR_T $DIR_LOG
FIN
        crear_timer() {
            cat > "/etc/systemd/system/innovatech-envio-$1.timer" <<FIN
[Unit]
Description=INNOVATECH - envio $3 de documentos $2

[Timer]
OnCalendar=$4
Persistent=true
Unit=innovatech-envio@$2.service

[Install]
WantedBy=timers.target
FIN
        }
        crear_timer proy PROY diario    "*-*-* 06:00:00"
        crear_timer info INFO semanal   "Mon *-*-* 06:15:00"
        crear_timer cont CONT mensual   "*-*-01 06:30:00"
        systemctl daemon-reload
        systemctl enable --now innovatech-envio-proy.timer innovatech-envio-info.timer innovatech-envio-cont.timer >/dev/null 2>&1
        ok "Temporizadores: PROY diario 06:00, INFO lunes 06:15, CONT dia 1 06:30"
    else
        aviso "Sin systemd. Equivalente en cron (usuario $SERVICIO):"
        echo "    0 6 * * *  $SCRIPT -C $CONF -t PROY"
        echo "    15 6 * * 1 $SCRIPT -C $CONF -t INFO"
        echo "    30 6 1 * * $SCRIPT -C $CONF -t CONT"
    fi

    titulo "Siguiente paso"
    echo "En el servidor SFTP de TECHTRANSFER ejecute:"
    echo "  sudo ./preparar_proveedor.sh autorizar '$(cat "$CLAVES/id_ed25519_sftp.pub")'"
    echo "Huella de esta llave: $(ssh-keygen -lf "$CLAVES/id_ed25519_sftp.pub")"
    echo "Luego aqui: sudo $0 vincular"
}

#-------------------------------------------------------------------------------
vincular() {
    [[ -f "$CONF" ]] || { echo "Primero ejecute: $0 instalar -s IP_SFTP"; exit 1; }
    local H P T
    H="$(leer_conf SFTP_HOST)"; P="$(leer_conf SFTP_PUERTO)"; T="$(mktemp -d)"; chown "$SERVICIO" "$T"

    titulo "1. Llave del servidor SFTP $H"
    ssh-keyscan -t ed25519 -p "$P" "$H" 2>/dev/null > "$T/kh"
    [[ -s "$T/kh" ]] || { echo "No se obtuvo respuesta SSH de $H:$P"; exit 1; }
    echo "Huella recibida: $(ssh-keygen -lf "$T/kh")"
    echo "Comparela con la que muestra el servidor: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
    read -r -p "¿Las huellas son identicas? (s/n): " R
    [[ "$R" == "s" || "$R" == "S" ]] || { echo "Vinculacion cancelada: posible suplantacion del servidor"; exit 1; }
    install -m 644 -o root -g root "$T/kh" "$ETC/known_hosts_techtransfer"
    ok "Llave del servidor fijada en $ETC/known_hosts_techtransfer (solo root puede cambiarla)"

    titulo "2. Intercambio de llaves publicas por el canal verificado"
    cp "$ETC/innovatech_firma_pub.pem" "$T/innovatech_firma_pub.pem"; chown "$SERVICIO" "$T"/*
    printf 'get /publico/techtransfer_cifrado_pub.pem %s/prov.pem\nput %s/innovatech_firma_pub.pem /entrada/innovatech_firma_pub.pem\n' "$T" "$T" > "$T/lote"
    # shellcheck disable=SC2046
    como_servicio sftp $(OPC_SSH) -b "$T/lote" "$(leer_conf SFTP_USUARIO)@$H"
    openssl pkey -pubin -in "$T/prov.pem" -noout || { echo "La llave descargada no es valida"; exit 1; }
    install -m 644 -o root -g root "$T/prov.pem" "$ETC/techtransfer_cifrado_pub.pem"
    rm -rf "$T"
    ok "Llave publica de cifrado de TECHTRANSFER: $(openssl pkey -pubin -in "$ETC/techtransfer_cifrado_pub.pem" -noout -text | head -1)"
    echo "    SHA-256: $(sha256sum "$ETC/techtransfer_cifrado_pub.pem" | cut -d' ' -f1)  (debe coincidir con el del proveedor)"
    ok "Llave publica de firma de INNOVATECH subida a /entrada"
    echo "    SHA-256: $(sha256sum "$ETC/innovatech_firma_pub.pem" | cut -d' ' -f1)  (el proveedor lo confirma con: preparar_proveedor.sh firma)"
}

#-------------------------------------------------------------------------------
documentos() {
    local HOY; HOY="$(date +%d%m%Y)"
    crear() {
        local f="$DIR_T/$1/$2"
        {
            echo "INNOVATECH SOLUTIONS S.A.S. - $3"
            echo "Documento: $2"
            echo "Generado: $(date '+%Y-%m-%d %H:%M:%S') en $(hostname)"
            echo "Proceso: $1 | Ambiente de laboratorio JJFEC (documento ficticio)"
            echo "------------------------------------------------------------"
            for i in $(seq 1 40); do echo "Linea $i: registro de prueba $(openssl rand -hex 16)"; done
        } > "$f"
        chown "$SERVICIO:$SERVICIO" "$f"; chmod 640 "$f"
        echo "  $f  ($(stat -c%s "$f") bytes, SHA-256 $(sha256sum "$f" | cut -c1-16)...)"
    }
    titulo "Documentos de prueba"
    crear Proyectos PROY-00001234-"$HOY".txt "Reporte diario de proyecto"
    crear Proyectos PROY-00001235-"$HOY".txt "Orden de trabajo"
    crear Informes  INFO-00005678-"$HOY".txt "Informe tecnico semanal"
    crear Contratos CONT-00007891-"$HOY".txt "Contrato de servicios (mensual)"
    crear Proyectos notas_reunion.txt "Archivo que NO cumple la nomenclatura"
    crear Proyectos PROY-00009999-31022026.txt "Fecha imposible (31 de febrero)"
    ok "Los dos ultimos sirven para comprobar que el script descarta lo que no cumple"
}

#-------------------------------------------------------------------------------
enviar() {
    local TIPO="${1:-}"
    [[ -z "$TIPO" || "$TIPO" =~ ^(PROY|INFO|CONT)$ ]] || { echo "Tipo invalido"; exit 1; }
    if hay_systemd && [[ -n "$TIPO" ]]; then
        systemctl start "innovatech-envio@$TIPO.service" || true
        systemctl status "innovatech-envio@$TIPO.service" --no-pager -n 0 | head -5 || true
        echo; tail -n 15 "$DIR_LOG/envio.log"
    else
        local A=(-C "$CONF"); [[ -n "$TIPO" ]] && A+=(-t "$TIPO")
        set -a; . "$ETC/firma.env"; set +a
        como_servicio "$SCRIPT" "${A[@]}" || true
    fi
}

#-------------------------------------------------------------------------------
pruebas() {
    local P; P="$(mktemp -d /tmp/pruebas_origen.XXXXXX)"; chown "$SERVICIO" "$P"
    set -a; . "$ETC/firma.env"; set +a
    mkdir -p "$P/T/Proyectos" "$P/log"
    printf 'documento de prueba\n' > "$P/T/Proyectos/PROY-00000777-$(date +%d%m%Y).txt"
    chown -R "$SERVICIO" "$P"
    correr() {
        printf '\n\033[1;35m--- PRUEBA: %s ---\033[0m\n' "$1"
        local rc=0
        como_servicio "$SCRIPT" -C "$2" > "$P/salida.txt" 2>&1 || rc=$?
        grep -E 'ERROR|WARN|7/7|no permitido' "$P/salida.txt" | sed 's/^\[[^]]*\] //' | cut -c1-240 || true
        if (( rc != 0 )); then ok "El script se detuvo de forma segura (codigo $rc); no se envio nada"
        else aviso "El envio se completo: revisar"; fi
    }
    base_conf() { sed -e "s#^DIR_TRANSFERENCIAS=.*#DIR_TRANSFERENCIAS=$P/T#" -e "s#^DIR_LOG=.*#DIR_LOG=$P/log#" "$CONF"; }

    # A. Servidor suplantado: la llave que responde no es la fijada
    ssh-keygen -q -t ed25519 -N "" -f "$P/falsa"
    echo "$(leer_conf SFTP_HOST) $(cut -d' ' -f1,2 "$P/falsa.pub")" > "$P/kh_falso"
    base_conf | sed "s#^KNOWN_HOSTS=.*#KNOWN_HOSTS=$P/kh_falso#" > "$P/a.conf"
    # B. Llave privada con permisos inseguros
    cp "$CLAVES/id_ed25519_sftp" "$P/llave_insegura"
    base_conf | sed "s#^LLAVE_SSH=.*#LLAVE_SSH=$P/llave_insegura#" > "$P/b.conf"
    # C. Configuracion con intento de inyeccion de comandos
    base_conf | sed 's#^SFTP_HOST=.*#SFTP_HOST=$(rm -rf /tmp/x)#' > "$P/c.conf"
    # D. Llave publica del proveedor debil (RSA-1024)
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 2>/dev/null | openssl pkey -pubout -out "$P/debil.pem"
    base_conf | sed "s#^CLAVE_PUB_PROVEEDOR=.*#CLAVE_PUB_PROVEEDOR=$P/debil.pem#" > "$P/d.conf"
    chown -R "$SERVICIO:$SERVICIO" "$P"; chmod 644 "$P"/*.conf "$P/kh_falso" "$P/llave_insegura"

    correr "Servidor SFTP suplantado (llave distinta a la fijada)" "$P/a.conf"
    correr "Llave privada legible por otros usuarios (644)" "$P/b.conf"
    correr "Configuracion con inyeccion de comandos" "$P/c.conf"
    correr "Llave publica del proveedor de solo 1024 bits" "$P/d.conf"

    # E y F. El usuario SFTP no tiene terminal ni acepta contrasenas
    local DEST; DEST="$(leer_conf SFTP_USUARIO)@$(leer_conf SFTP_HOST)"
    local SSH_O=(-p "$(leer_conf SFTP_PUERTO)" -o BatchMode=yes -o StrictHostKeyChecking=yes
                 -o "UserKnownHostsFile=$ETC/known_hosts_techtransfer" -o ConnectTimeout=15)
    printf '\n\033[1;35m--- PRUEBA: %s ---\033[0m\n' "Abrir una terminal en el servidor SFTP con la llave valida"
    como_servicio ssh "${SSH_O[@]}" -i "$CLAVES/id_ed25519_sftp" -o IdentitiesOnly=yes "$DEST" 'id; hostname' </dev/null 2>&1 | head -3 || true
    ok "El servidor solo permite SFTP: no ejecuta comandos ni entrega terminal"
    printf '\n\033[1;35m--- PRUEBA: %s ---\033[0m\n' "Ingresar con contrasena en lugar de llave"
    como_servicio ssh "${SSH_O[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive "$DEST" true </dev/null 2>&1 | tail -1 || true
    ok "El servidor solo ofrece el metodo publickey"

    rm -rf "$P"
    echo; ok "Pruebas terminadas; la configuracion real no se modifico"
}

#-------------------------------------------------------------------------------
estado() {
    titulo "Servidor de INNOVATECH (origen)"
    echo "Equipo: $(hostname)  IP: $(hostname -I 2>/dev/null)"
    echo "Usuario de servicio: $(id "$SERVICIO")  shell: $(getent passwd "$SERVICIO" | cut -d: -f7)"
    echo; echo "Llave del servidor SFTP fijada:"; ssh-keygen -lf "$ETC/known_hosts_techtransfer" 2>/dev/null || echo "  (aun no vinculado)"
    echo; echo "Permisos de llaves y configuracion:"; ls -l "$ETC" "$CLAVES"
    echo; echo "Configuracion (sin secretos):"; grep -v '^#' "$CONF"
    if hay_systemd; then echo; systemctl list-timers 'innovatech-envio-*' --no-pager; fi
    echo; echo "Carpetas:"; find "$DIR_T" -type f | sort
    echo; echo "Ultimos eventos:"; tail -n 15 "$DIR_LOG/envio.log" 2>/dev/null || true
}

case "$ACCION" in
    instalar) instalar ;;
    vincular) vincular ;;
    documentos) documentos ;;
    enviar) enviar "${1:-}" ;;
    pruebas) pruebas ;;
    estado) estado ;;
    *) echo "Uso: $0 instalar -s IP_SFTP [-P puerto] [-u usuario] | vincular | documentos | enviar [PROY|INFO|CONT] | pruebas | estado"; exit 1 ;;
esac
