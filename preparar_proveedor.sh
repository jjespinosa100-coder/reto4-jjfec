#!/bin/bash
#===============================================================================
# TECHTRANSFER S.A.S. - preparar_proveedor.sh (Reto 4)
# Prepara el servidor SFTP del proveedor (CentOS Stream 8 / Rocky / Ubuntu).
# Se ejecuta como root una sola vez; no forma parte del envio automatico.
#
#   instalar [-o IP_ORIGEN] [-u usuario]   usuario enjaulado, llaves RSA, sshd,
#                                          script de recepcion y temporizador
#   firma                                  instala la llave publica de firma
#                                          que INNOVATECH subio a entrada/
#   pruebas                                ataques controlados contra el receptor
#   estado                                 resumen para la evidencia
#
# Curso: Algoritmos y Modelos Criptograficos (219027) - UNAD
#===============================================================================

set -euo pipefail
umask 022

ACCION="${1:-}"; shift || true
USUARIO="innovatech"
IP_ORIGEN="192.168.42.10"   # IP con la que llega INNOVATECH (WAN de pfSense-BOG, por NAT)
RAIZ="/sftp"
DIR_CLAVES="/etc/techtransfer/claves"
DIR_BASE="/srv/techtransfer"
RECEPTOR="/usr/local/sbin/techtransfer_recepcion.sh"
ORIGEN_SCRIPTS="$(cd "$(dirname "$0")" && pwd)"

[[ -f /etc/techtransfer/proveedor.conf ]] && . /etc/techtransfer/proveedor.conf
while getopts ":o:u:" o; do
    case "$o" in o) IP_ORIGEN="$OPTARG" ;; u) USUARIO="$OPTARG" ;; *) ;; esac
done
shift $((OPTIND-1))
[[ "$IP_ORIGEN" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ && "$USUARIO" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "IP o usuario invalidos"; exit 1; }

[[ $EUID -eq 0 ]] || { echo "Ejecute como root (sudo)"; exit 1; }
CHROOT="$RAIZ/$USUARIO"
ENTRADA="$CHROOT/entrada"

titulo() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()     { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
aviso()  { printf '\033[1;33m[AVISO]\033[0m %s\n' "$*"; }
hay_systemd() { [[ -d /run/systemd/system ]]; }

reparar_repos_centos8() {
    # CentOS Stream 8 termino su soporte (mayo 2024): los repositorios pasaron a vault.
    if grep -qs 'CentOS Stream release 8' /etc/centos-release && grep -qs '^mirrorlist=' /etc/yum.repos.d/CentOS-Stream-*.repo; then
        sed -i 's/^mirrorlist=/#mirrorlist=/; s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/CentOS-Stream-*.repo
        aviso "Repositorios de CentOS Stream 8 apuntados a vault.centos.org"
    fi
}

instalar_paquetes() {
    local faltan=()
    command -v sshd >/dev/null 2>&1 || [[ -x /usr/sbin/sshd ]] || faltan+=(openssh-server)
    for h in tar openssl flock shred; do command -v "$h" >/dev/null 2>&1 || faltan+=("$h"); done
    (( ${#faltan[@]} == 0 )) && return 0
    if command -v dnf >/dev/null 2>&1; then
        reparar_repos_centos8
        dnf -y install openssh-server tar openssl util-linux coreutils
    else
        apt-get update -qq && apt-get install -y openssh-server tar openssl util-linux coreutils
    fi
}

reiniciar_sshd() {
    /usr/sbin/sshd -t || { echo "La configuracion de sshd tiene errores; no se reinicia"; exit 1; }
    if hay_systemd; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
    else
        aviso "Sin systemd: inicie sshd a mano (/usr/sbin/sshd)"
    fi
}

#-------------------------------------------------------------------------------
instalar() {
    titulo "1. Paquetes"
    instalar_paquetes; ok "openssh-server, tar y openssl disponibles ($(ssh -V 2>&1 | cut -d, -f1))"

    titulo "2. Usuario SFTP enjaulado: $USUARIO"
    local NOLOGIN; NOLOGIN="$(command -v nologin || echo /sbin/nologin)"
    id "$USUARIO" >/dev/null 2>&1 || useradd -M -d "$CHROOT" -s "$NOLOGIN" "$USUARIO"
    passwd -l "$USUARIO" >/dev/null 2>&1 || true
    mkdir -p "$ENTRADA" "$CHROOT/publico"
    chown root:root "$RAIZ" "$CHROOT" "$CHROOT/publico"; chmod 755 "$RAIZ" "$CHROOT" "$CHROOT/publico"
    chown "$USUARIO:$USUARIO" "$ENTRADA"; chmod 700 "$ENTRADA"
    ok "Jaula $CHROOT (root:755), entrada/ escribible solo por $USUARIO, publico/ solo lectura; contrasena bloqueada"

    titulo "3. Llaves RSA-4096 de cifrado de TECHTRANSFER"
    mkdir -p "$DIR_CLAVES"; chmod 700 "$DIR_CLAVES"
    printf 'USUARIO=%s\nIP_ORIGEN=%s\n' "$USUARIO" "$IP_ORIGEN" > /etc/techtransfer/proveedor.conf
    chmod 600 /etc/techtransfer/proveedor.conf
    if [[ ! -f "$DIR_CLAVES/techtransfer_cifrado.pem" ]]; then
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$DIR_CLAVES/techtransfer_cifrado.pem" 2>/dev/null
    fi
    chmod 600 "$DIR_CLAVES/techtransfer_cifrado.pem"
    openssl pkey -in "$DIR_CLAVES/techtransfer_cifrado.pem" -pubout -out "$CHROOT/publico/techtransfer_cifrado_pub.pem"
    chmod 644 "$CHROOT/publico/techtransfer_cifrado_pub.pem"
    ok "Privada en $DIR_CLAVES (600); publica publicada en publico/"
    echo "    SHA-256 de la llave publica: $(sha256sum "$CHROOT/publico/techtransfer_cifrado_pub.pem" | cut -d' ' -f1)"

    titulo "4. Configuracion de sshd"
    mkdir -p /etc/ssh/authorized_keys; chmod 755 /etc/ssh/authorized_keys
    touch "/etc/ssh/authorized_keys/$USUARIO"; chmod 644 "/etc/ssh/authorized_keys/$USUARIO"
    [[ -f /etc/ssh/ssh_host_ed25519_key ]] || ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
    [[ -f /etc/ssh/sshd_config.reto4.bak ]] || cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.reto4.bak
    sed -i '/^# >>> RETO4 TECHTRANSFER/,/^# <<< RETO4 TECHTRANSFER/d' /etc/ssh/sshd_config
    cat >> /etc/ssh/sshd_config <<FIN
# >>> RETO4 TECHTRANSFER
Match User $USUARIO
    AuthorizedKeysFile /etc/ssh/authorized_keys/%u
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PubkeyAcceptedKeyTypes ssh-ed25519
    PasswordAuthentication no
    ChrootDirectory $CHROOT
    ForceCommand internal-sftp -l INFO -u 0077
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
# <<< RETO4 TECHTRANSFER
FIN
    if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
        # internal-sftp corre en el dominio sftpd_t: necesita permiso para escribir
        # en la jaula (el control fino lo siguen haciendo los permisos y el chroot)
        restorecon -R /etc/ssh/authorized_keys 2>/dev/null || true
        setsebool -P ssh_chroot_rw_homedirs on 2>/dev/null || true
        setsebool -P sftpd_full_access on 2>/dev/null || true
        ok "SELinux Enforcing: llaves autorizadas en /etc/ssh y booleanos de SFTP enjaulado activos"
    fi
    if hay_systemd && systemctl is-active -q firewalld 2>/dev/null; then
        firewall-cmd -q --permanent --add-service=ssh && firewall-cmd -q --reload
        ok "firewalld: servicio ssh permitido"
    fi
    reiniciar_sshd
    ok "sshd: solo llave publica Ed25519, sin contrasena, sin terminal ni tuneles, enjaulado en $CHROOT"
    echo "    Huella de la llave del servidor (compararla en INNOVATECH):"
    echo "    $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)"

    titulo "5. Script de recepcion y temporizador"
    install -m 750 -o root -g root "$ORIGEN_SCRIPTS/techtransfer_recepcion.sh" "$RECEPTOR"
    mkdir -p "$DIR_BASE"/{recibidos,cuarentena,archivo} /var/lib/techtransfer
    chmod 700 "$DIR_BASE" /var/lib/techtransfer
    if hay_systemd; then
        cat > /etc/systemd/system/techtransfer-recepcion.service <<FIN
[Unit]
Description=TECHTRANSFER - verificacion y descifrado de paquetes de INNOVATECH

[Service]
Type=oneshot
ExecStart=$RECEPTOR -d $ENTRADA
SuccessExitStatus=16
PrivateTmp=yes
NoNewPrivileges=yes
FIN
        cat > /etc/systemd/system/techtransfer-recepcion.timer <<FIN
[Unit]
Description=TECHTRANSFER - revisa la carpeta de entrada cada 2 minutos

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
FIN
        systemctl daemon-reload
        systemctl enable --now techtransfer-recepcion.timer >/dev/null 2>&1
        ok "Temporizador techtransfer-recepcion.timer activo (cada 2 minutos)"
    else
        aviso "Sin systemd: ejecute $RECEPTOR -d $ENTRADA a mano"
    fi

    titulo "Pendiente"
    echo "  a) Pegar la llave publica SSH de INNOVATECH (una linea ssh-ed25519 ...):"
    echo "     $0 autorizar 'ssh-ed25519 AAAA... innovatech@...'"
    echo "  b) Cuando INNOVATECH suba su llave de firma:  $0 firma"
}

#-------------------------------------------------------------------------------
autorizar() {
    local LINEA="${1:-}"
    if [[ -z "$LINEA" ]]; then
        echo "Pegue la linea de la llave publica de INNOVATECH y presione Enter:"; read -r LINEA
    fi
    [[ "$LINEA" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || { echo "No es una llave publica ssh-ed25519 valida"; exit 1; }
    local TMP; TMP="$(mktemp)"; echo "$LINEA" > "$TMP"
    ssh-keygen -lf "$TMP" >/dev/null 2>&1 || { rm -f "$TMP"; echo "La llave no es valida"; exit 1; }
    echo "Huella de la llave recibida: $(ssh-keygen -lf "$TMP")"; rm -f "$TMP"
    echo "from=\"$IP_ORIGEN\",restrict $LINEA" > "/etc/ssh/authorized_keys/$USUARIO"
    chmod 644 "/etc/ssh/authorized_keys/$USUARIO"; chown root:root "/etc/ssh/authorized_keys/$USUARIO"
    ok "Llave autorizada solo desde $IP_ORIGEN y sin terminal, reenvio ni tuneles (restrict)"
    cat "/etc/ssh/authorized_keys/$USUARIO" | cut -c1-90; echo "..."
}

#-------------------------------------------------------------------------------
firma() {
    local F="$ENTRADA/innovatech_firma_pub.pem"
    [[ -f "$F" ]] || { echo "INNOVATECH aun no ha subido $F"; exit 1; }
    openssl pkey -pubin -in "$F" -noout 2>/dev/null || { echo "El archivo no es una llave publica valida"; exit 1; }
    echo "Llave de firma recibida: $(openssl pkey -pubin -in "$F" -noout -text | head -1)"
    echo "SHA-256: $(sha256sum "$F" | cut -d' ' -f1)"
    read -r -p "¿Coincide con el SHA-256 que muestra el servidor de INNOVATECH? (s/n): " R
    [[ "$R" == "s" || "$R" == "S" ]] || { mv "$F" "$DIR_BASE/cuarentena/"; echo "Rechazada y movida a cuarentena"; exit 1; }
    install -m 644 -o root -g root "$F" "$DIR_CLAVES/innovatech_firma_pub.pem"; rm -f "$F"
    ok "Llave publica de firma de INNOVATECH instalada en $DIR_CLAVES"
}

#-------------------------------------------------------------------------------
pruebas() {
    local P="/root/pruebas_reto4" ULT
    ULT="$(find "$DIR_BASE/archivo" -name '*.tar' -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)"
    [[ -n "$ULT" ]] || { echo "Primero debe recibirse al menos un paquete valido"; exit 1; }
    rm -rf "$P"; mkdir -p "$P"; chmod 700 "$P"
    local B; B="$(basename "$ULT" .tar)"; local N="${B%_*_*}"
    echo "Paquete legitimo usado como base: $(basename "$ULT")"
    prueba() {
        printf '\n\033[1;35m--- PRUEBA: %s ---\033[0m\n' "$1"
        local rc=0
        "$RECEPTOR" -p "$2" -q "$P/cuarentena" -o "$P/salida" -a "$P/archivo" > "$P/salida.txt" 2>&1 || rc=$?
        grep -E 'RECHAZADO|/5 ' "$P/salida.txt" | sed 's/^\[[^]]*\] //' || true
        if (( rc != 0 )); then ok "Paquete rechazado y enviado a cuarentena (codigo $rc)"
        else aviso "El paquete fue ACEPTADO: revisar"; fi
    }
    # A. Reenvio del mismo paquete
    cp "$ULT" "$P/${B}.tar"
    prueba "Reenvio de un paquete ya procesado" "$P/${B}.tar"
    # B. Se altera el cifrado y se recalcula el hash (atacante sin la llave privada)
    mkdir -p "$P/b"; tar -xf "$ULT" -C "$P/b"
    printf 'X' | dd of="$P/b/$N.enc" bs=1 seek=100 conv=notrunc status=none
    ( cd "$P/b" && sha256sum "$N.enc" "$N.key.enc" > "$N.sha256" )
    tar -cf "$P/${N}_20990101_000001.tar" -C "$P/b" "$N.enc" "$N.key.enc" "$N.sha256" "$N.sha256.sig"
    prueba "Archivo alterado con hash recalculado por el atacante" "$P/${N}_20990101_000001.tar"
    # C. Se altera el cifrado sin tocar el hash
    mkdir -p "$P/c"; tar -xf "$ULT" -C "$P/c"
    printf 'X' | dd of="$P/c/$N.enc" bs=1 seek=100 conv=notrunc status=none
    tar -cf "$P/${N}_20990101_000002.tar" -C "$P/c" "$N.enc" "$N.key.enc" "$N.sha256" "$N.sha256.sig"
    prueba "Archivo alterado en el camino (hash original)" "$P/${N}_20990101_000002.tar"
    # D. Paquete con un archivo de mas (intento de colar contenido)
    mkdir -p "$P/d"; tar -xf "$ULT" -C "$P/d"; echo 'malicioso' > "$P/d/extra.sh"
    tar -cf "$P/${N}_20990101_000003.tar" -C "$P/d" "$N.enc" "$N.key.enc" "$N.sha256" "$N.sha256.sig" extra.sh
    prueba "Paquete con un archivo adicional" "$P/${N}_20990101_000003.tar"
    # E. Nombre fuera de la nomenclatura
    cp "$ULT" "$P/FACT-00000001-01012026_20990101_000004.tar"
    prueba "Nombre fuera de la nomenclatura" "$P/FACT-00000001-01012026_20990101_000004.tar"
    echo; ok "Pruebas terminadas. Detalle en /var/lib/techtransfer/recepcion.log"
}

#-------------------------------------------------------------------------------
estado() {
    titulo "Servidor SFTP de TECHTRANSFER"
    echo "Equipo: $(hostname)  IP: $(hostname -I 2>/dev/null)"
    echo "Llave del servidor: $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)"
    echo "Usuario: $(id "$USUARIO")  shell: $(getent passwd "$USUARIO" | cut -d: -f7)"
    echo "Contrasena: $(passwd -S "$USUARIO" 2>/dev/null | awk '{print $2}') (L/LK = bloqueada)"
    command -v getenforce >/dev/null 2>&1 && echo "SELinux: $(getenforce)"
    echo; echo "Llaves autorizadas:"; cut -c1-100 "/etc/ssh/authorized_keys/$USUARIO"
    echo; echo "Bloque de sshd:"; sed -n '/^# >>> RETO4/,/^# <<< RETO4/p' /etc/ssh/sshd_config
    echo; echo "Permisos:"; ls -ld "$RAIZ" "$CHROOT" "$ENTRADA" "$CHROOT/publico" "$DIR_CLAVES"; ls -l "$DIR_CLAVES"
    hay_systemd && { echo; systemctl list-timers techtransfer-recepcion.timer --no-pager; }
    echo; echo "Ultimos eventos:"; tail -n 15 /var/lib/techtransfer/recepcion.log 2>/dev/null || true
}

case "$ACCION" in
    instalar) instalar ;;
    autorizar) autorizar "${1:-}" ;;
    firma) firma ;;
    pruebas) pruebas ;;
    estado) estado ;;
    *) echo "Uso: $0 instalar [-o IP_ORIGEN] [-u usuario] | autorizar 'ssh-ed25519 ...' | firma | pruebas | estado"; exit 1 ;;
esac
