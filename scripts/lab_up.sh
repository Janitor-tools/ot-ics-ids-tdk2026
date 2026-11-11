#!/usr/bin/env bash
# lab_up.sh -- a labor hidegindites utani, nem perzisztens allapotanak
# helyreallitasa (M2b). A laptop Git Bash-ebol fut, a ~/.ssh/config
# host-aliasait hasznalja (siem, sensor, plc, redteam; ProxyJump labhost).
#
# Hasznalat:
#   bash scripts/lab_up.sh            # vegrehajtas
#   bash scripts/lab_up.sh --dry-run  # csak kiirja a parancsokat, SSH nelkul
#
# Az augusztusi (2026-08-22) kezi eljarast kodolja, lasd
# docs/tdk/ELTERESNAPLO.md E-01..E-03, E-14:
#   (indulaskor: git HEAD, dirty-tree ellenorzes a scripts/ alatt, a szkript
#    sajat sha256-ja, futtato whoami@hostname -- ez naplozva)
#   L0: chronyc makestep mind a 4 VM-en, majd Leap Normal + forras-ellenorzes
#       + a laptophoz mert oraelteres <= 3 s (kulonben HIBA; E-31). A SIEM mar
#       kulso NTP-t (pool.ntp.org) kovet, ezert a Stratum 10 nem elofeltetel.
#   L0b elofeltetel: apt-daily(-upgrade).timer NEM enabled egyik VM-en sem (E-06)
#   L1 Sensor:      zeekctl start, ha a Zeek nem "running" (NEM deploy/install)
#   L1b Sensor:     csak olvasas -- zeekctl status + a capture_loss.log utolso sora
#   L2 Target-PLC:  OpenPLC futtatokornyezet inditasa a web-API-n (login + /start_plc)
#   L3 Red-Team:    a 192.168.1.51/24 alias felvetele az enp0s8-ra (nem perzisztens)
#   L4 szkriptek:   a Red-Team attack_runner.py / benign_generator.py == HEAD
#   L5 osszesites
#
# TILOS ebben a szkriptben (szandekosan nincs benne):
#   - csomagkezelo-hivas (apt, apt-get, dpkg -i, pip, zkg install/upgrade),
#   - perzisztens konfiguracio irasa (netplan, node.cfg, zeekctl.cfg,
#     suricata.yaml, filebeat.yml, chrony.conf stb.),
#   - systemctl enable / disable,
#   - adatbazis-iras (openplc.db, Elasticsearch-index/-beallitas),
#   - perzisztens oraallitas (chrony.conf iras), fajlmasolas a VM-ekre.
# (A chronyc makestep az L0-ban SZANDEKOS es megengedett -- minden meres elott
#  a 4 VM orajat a kozos referenciahoz lepteti; NEM perzisztens, E-31.)
# Az OpenPLC hitelesito adatai az OPENPLC_USER / OPENPLC_PASS kornyezeti
# valtozobol jonnek, vagy read -s-sel kerul bekeresre; SOHA nem kerulnek
# kiirasra, naplozasra, sem a repoba.

set -euo pipefail

DRY_RUN=0
case "${1:-}" in
    --dry-run) DRY_RUN=1 ;;
    "") ;;
    *) echo "Ismeretlen kapcsolo: $1 (csak --dry-run)" >&2; exit 64 ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$REPO/results/lab-up-$(date -u +%Y%m%dT%H%M%SZ).log"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
SIEM_MGMT_IP="192.168.56.10"
ALIAS_IP="192.168.1.51/24"
ATTACKER_IP="192.168.1.50/24"
OT_IF="enp0s8"
REDTEAM_DIR="/home/ot"

mkdir -p "$REPO/results"
exec > >(tee -a "$LOG") 2>&1
# fd 3: a dry-run uzenetek ide mennek, hogy a $(...) ne nyelje el oket
exec 3>&1

ts() { date -u +%FT%TZ; }
log() { echo "[$(ts)] $*"; }

# Osszesito tablazat sorai (L5)
S_NAME=(); S_BEFORE=(); S_ACTION=(); S_AFTER=(); S_RESULT=()
record() { S_NAME+=("$1"); S_BEFORE+=("$2"); S_ACTION+=("$3"); S_AFTER+=("$4"); S_RESULT+=("$5"); }

summary() {
    log "=== L5 osszesites ==="
    printf '| %-4s | %-34s | %-30s | %-34s | %-7s |\n' "Lepes" "Allapot elotte" "Muvelet" "Allapot utana" "Eredm."
    printf '|------|------------------------------------|--------------------------------|------------------------------------|---------|\n'
    local i
    for i in "${!S_NAME[@]}"; do
        printf '| %-4s | %-34s | %-30s | %-34s | %-7s |\n' \
            "${S_NAME[$i]}" "${S_BEFORE[$i]}" "${S_ACTION[$i]}" "${S_AFTER[$i]}" "${S_RESULT[$i]}"
    done
    log "Naplo: $LOG"
}

fail() {
    # $1 lepes, $2 elotte, $3 muvelet, $4 uzenet
    record "$1" "$2" "$3" "$4" "HIBA"
    log "HIBA ($1): $4"
    summary
    exit 1
}

# Tavoli parancs. Dry-run modban csak kiirja (fd 3), es ures kimenettel ter vissza.
rsh() {
    local host=$1; shift
    if (( DRY_RUN )); then
        printf '[DRY-RUN] ssh %s %s %q\n' "${SSH_OPTS[*]}" "$host" "$*" >&3
        return 0
    fi
    ssh "${SSH_OPTS[@]}" "$host" "$*"
}

step_begin() { log ">>> $1 kezdete"; }
step_end() { log "<<< $1 vege"; }

log "lab_up.sh indul (dry-run=$DRY_RUN), repo=$REPO"

# ---------------------------------------------------------------- provenance
log "git HEAD: $(git -C "$REPO" rev-parse HEAD)"
porcelain=$(git -C "$REPO" status --porcelain)
log "git status --porcelain:"
printf '%s\n' "${porcelain:-(tiszta)}"
log "lab_up.sh sha256: $(sha256sum < "$0" | cut -d' ' -f1)"
log "futtato: $(whoami)@$(hostname)"
dirty_scripts=$(git -C "$REPO" status --porcelain -- scripts/)
if [[ -n $dirty_scripts ]]; then
    if (( DRY_RUN )); then
        # dry-run nem valtoztat semmit, ezert itt csak figyelmeztet
        log "FIGYELMEZTETES (dry-run): dirty tree a scripts/ alatt -- eles futas itt megallna"
    else
        log "HIBA: dirty tree a scripts/ alatt -- commitold, mielott eles futas indul"
        exit 1
    fi
fi

# ---------------------------------------------------------------- L0
step_begin "L0 (chrony: makestep + ellenorzes)"
# E-31: minden meres elott a 4 VM oraja a kozos referenciahoz lep (chronyc
# makestep), majd Leap Normal + forras-ellenorzes, vegul a laptophoz mert
# oraelteres <= 3 s. A SIEM mar kulso NTP-t kovet, a Stratum 10 nem elofeltetel.
l0_state=""
l0_skew=""
for h in siem sensor plc redteam; do
    rsh "$h" "sudo -n chronyc makestep" >/dev/null 2>&1 || true
done
for h in siem sensor plc redteam; do
    out=$(rsh "$h" "chronyc tracking") || fail "L0" "$h: chronyc hiba" "-" "chronyc tracking sikertelen ($h)"
    if (( DRY_RUN )); then continue; fi
    [[ $out =~ Leap\ status[[:space:]]*:\ Normal ]] \
        || fail "L0" "$h: Leap != Normal" "-" "$h: Leap status nem Normal (nem avatkozunk be)"
    if [[ $h != siem ]]; then
        # a kliensek forrasa a SIEM; a SIEM-nek most kulso NTP a forrasa (E-31)
        [[ $out == *"($SIEM_MGMT_IP)"* ]] \
            || fail "L0" "$h: forras != SIEM" "-" "$h: a chrony forrasa nem a SIEM ($SIEM_MGMT_IP)"
    fi
    # a laptophoz mert oraelteres (abszolut, masodpercben) <= 3 s (E-31)
    lap=$(date -u +%s)
    vm=$(rsh "$h" "date -u +%s") || fail "L0" "$h: date hiba" "-" "date -u sikertelen ($h)"
    [[ $vm =~ ^[0-9]+$ ]] || fail "L0" "$h: date formatum" "-" "date -u nem szam ($h): $vm"
    d=$(( lap > vm ? lap - vm : vm - lap ))
    log "$h: |laptop - VM| = ${d}s"
    (( d <= 3 )) || fail "L0" "$h: elteres ${d}s > 3s" "chronyc makestep" "$h: a laptophoz mert oraelteres ${d}s > 3s (E-31; szinkronizalj ujra)"
    l0_state+="$h "
    l0_skew+="$h=${d}s "
done
if (( DRY_RUN )); then
    record "L0" "(dry-run)" "chronyc makestep + ellenorzes" "(dry-run)" "DRY-RUN"
else
    record "L0" "Leap Normal, forras SIEM: ${l0_state% }" "chronyc makestep (4 VM)" "laptop-elteres: ${l0_skew% }" "OK"
fi
step_end "L0 (chrony: makestep + ellenorzes)"

# ---------------------------------------------------------------- L0b
step_begin "L0b (apt-idozitok)"
l0b_bad=""
for h in siem sensor plc redteam; do
    out=$(rsh "$h" "systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer") || true
    if (( DRY_RUN )); then continue; fi
    log "$h: $(echo $out)"
    # a "disabled" is tartalmazza az "enabled" szot, ezert soronkent pontos egyezes
    while IFS= read -r line; do
        [[ $line == enabled ]] && l0b_bad+="$h "
    done <<< "$out"
done
if (( DRY_RUN )); then
    record "L0b" "(dry-run)" "ellenorzes" "(dry-run)" "DRY-RUN"
elif [[ -n $l0b_bad ]]; then
    fail "L0b" "enabled: ${l0b_bad% }" "-" "apt-idozito engedelyezve: ${l0b_bad% } (E-06; a SIEM-en kezi lepes kell)"
else
    record "L0b" "mind disabled" "nincs (csak ellenorzes)" "valtozatlan" "OK"
fi
step_end "L0b (apt-idozitok)"

# ---------------------------------------------------------------- L1
step_begin "L1 (Sensor: Zeek)"
zeek_running() {
    local st
    st=$(rsh sensor "sudo -n /opt/zeek/bin/zeekctl status") || true
    [[ $st =~ [[:space:]]running[[:space:]] ]]
}
if (( ! DRY_RUN )) && zeek_running; then
    record "L1" "running" "kihagyva" "running" "OK"
else
    before="nem running"
    (( DRY_RUN )) && before="(dry-run)"
    log "zeekctl start (augusztusi eljaras; NEM deploy, NEM install)"
    rsh sensor "sudo -n /opt/zeek/bin/zeekctl start" || fail "L1" "$before" "zeekctl start" "a zeekctl start hibaval tert vissza"
    if (( DRY_RUN )); then
        rsh sensor "sudo -n /opt/zeek/bin/zeekctl status" >/dev/null
        rsh sensor "pgrep -a zeek" >/dev/null
        record "L1" "$before" "zeekctl start" "(dry-run)" "DRY-RUN"
    else
        zeek_running || fail "L1" "$before" "zeekctl start" "a zeekctl status nem 'running'"
        rsh sensor "pgrep -a zeek" || fail "L1" "$before" "zeekctl start" "pgrep zeek: nincs folyamat"
        record "L1" "$before" "zeekctl start" "running + pgrep ok" "OK"
    fi
fi
step_end "L1 (Sensor: Zeek)"

# ---------------------------------------------------------------- L1b
step_begin "L1b (Sensor: Zeek allapot, csak olvasas)"
zst=$(rsh sensor "sudo -n /opt/zeek/bin/zeekctl status") || true
cl=$(rsh sensor "test -f /opt/zeek/spool/zeek/capture_loss.log && tail -n 1 /opt/zeek/spool/zeek/capture_loss.log || echo '(nincs capture_loss.log)'") || true
if (( DRY_RUN )); then
    record "L1b" "(dry-run)" "olvasas" "(dry-run)" "DRY-RUN"
else
    printf '%s\n' "$zst"
    log "capture_loss utolso sor: $cl"
    record "L1b" "-" "nincs (csak olvasas)" "lasd naplo" "OK"
fi
step_end "L1b (Sensor: Zeek allapot, csak olvasas)"

# ---------------------------------------------------------------- L2
step_begin "L2 (Target-PLC: OpenPLC RUN)"
plc_listening() {
    local out
    out=$(rsh plc "ss -ltn") || true
    [[ $out =~ :502[[:space:]] && $out =~ :102[[:space:]] ]]
}
# Tavoli resz: a hitelesito adatokat stdin-rol olvassa (nem argv, nem fajl),
# a cookie-jar ideiglenes, kilepeskor torlodik. Az adatbazist nem modositja.
read -r -d '' PLC_REMOTE <<'EOS' || true
set -euo pipefail
IFS= read -r U
IFS= read -r P
J=$(mktemp)
trap 'rm -f "$J"' EXIT
B=http://127.0.0.1:8080
curl -s -o /dev/null -c "$J" -b "$J" "$B/login"
code=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -c "$J" -b "$J" \
    --data-urlencode "username@"<(printf %s "$U") \
    --data-urlencode "password@"<(printf %s "$P") "$B/login")
unset U P
echo "login: $code"
code=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -c "$J" -b "$J" "$B/start_plc")
echo "start_plc: $code"
case "$code" in
    *login*) echo "nincs bejelentkezve (hibas hitelesito adat?)"; exit 2 ;;
esac
EOS
if (( ! DRY_RUN )) && plc_listening; then
    record "L2" ":502 es :102 figyel" "kihagyva" ":502 es :102 figyel" "OK"
else
    before=":502/:102 nem figyel"
    if (( DRY_RUN )); then
        before="(dry-run)"
        log "[DRY-RUN] hitelesito adatok: OPENPLC_USER/OPENPLC_PASS vagy read -s (nem kerul kiirasra)"
        printf '[DRY-RUN] ssh %s plc bash -c <PLC_REMOTE: login + GET /start_plc a localhoston, cookie-jarral; adatok stdin-en>\n' "${SSH_OPTS[*]}" >&3
        rsh plc "ss -ltn" >/dev/null
        record "L2" "$before" "login + /start_plc" "(dry-run)" "DRY-RUN"
    else
        u="${OPENPLC_USER:-}"; p="${OPENPLC_PASS:-}"
        if [[ -z $u ]]; then read -r -p "OpenPLC felhasznalo: " u </dev/tty; fi
        if [[ -z $p ]]; then read -r -s -p "OpenPLC jelszo: " p </dev/tty; echo; fi
        printf '%s\n%s\n' "$u" "$p" \
            | ssh "${SSH_OPTS[@]}" plc "bash -c $(printf %q "$PLC_REMOTE")" \
            || { unset u p; fail "L2" "$before" "login + /start_plc" "a web-API hivas sikertelen"; }
        unset u p
        ok=0
        for _ in 1 2 3 4 5 6; do
            if plc_listening; then ok=1; break; fi
            sleep 5
        done
        (( ok )) || fail "L2" "$before" "login + /start_plc" ":502 vagy :102 nem figyel 30 s utan"
        rsh plc "ss -ltn | grep -E ':502 |:102 '"
        record "L2" "$before" "login + /start_plc" ":502 es :102 figyel" "OK"
    fi
fi
step_end "L2 (Target-PLC: OpenPLC RUN)"

# ---------------------------------------------------------------- L3
step_begin "L3 (Red-Team: .51 alias)"
alias_ok() {
    local out
    out=$(rsh redteam "ip -br addr show $OT_IF") || true
    [[ $out == *"$ATTACKER_IP"* && $out == *"$ALIAS_IP"* ]]
}
if (( ! DRY_RUN )) && alias_ok; then
    record "L3" ".50 es .51 jelen" "kihagyva" ".50 es .51 jelen" "OK"
else
    before=".51 hianyzik"
    (( DRY_RUN )) && before="(dry-run)"
    rsh redteam "sudo -n ip addr add $ALIAS_IP dev $OT_IF" \
        || fail "L3" "$before" "ip addr add .51" "az ip addr add sikertelen"
    if (( DRY_RUN )); then
        rsh redteam "ip -br addr show $OT_IF" >/dev/null
        record "L3" "$before" "ip addr add .51 (nem perz.)" "(dry-run)" "DRY-RUN"
    else
        alias_ok || fail "L3" "$before" "ip addr add .51" "az enp0s8-on nem lathato a .50 es a .51"
        rsh redteam "ip -br addr show $OT_IF"
        record "L3" "$before" "ip addr add .51 (nem perz.)" ".50 es .51 jelen" "OK"
    fi
fi
step_end "L3 (Red-Team: .51 alias)"

# ---------------------------------------------------------------- L4
step_begin "L4 (Red-Team szkriptek == HEAD)"
l4_bad=""
for f in attack_runner.py benign_generator.py; do
    if (( DRY_RUN )); then
        printf '[DRY-RUN] git -C %q show HEAD:scripts/%s | sha256sum\n' "$REPO" "$f" >&3
        rsh redteam "sha256sum $REDTEAM_DIR/$f" >/dev/null
        continue
    fi
    want=$(git -C "$REPO" show "HEAD:scripts/$f" | sha256sum | cut -d' ' -f1)
    have=$(rsh redteam "sha256sum $REDTEAM_DIR/$f" | cut -d' ' -f1) || have="(nem olvashato)"
    log "$f: HEAD=$want VM=$have"
    [[ $want == "$have" ]] || l4_bad+="$f "
done
if (( DRY_RUN )); then
    record "L4" "(dry-run)" "sha256 osszevetes" "(dry-run)" "DRY-RUN"
elif [[ -n $l4_bad ]]; then
    # nem telepit: a frissites kulon, jovahagyando lepes (deploy_red_team_scripts.sh)
    fail "L4" "elter: ${l4_bad% }" "nincs (nem telepit)" "a VM-en levo szkript nem egyezik a HEAD-del: ${l4_bad% }"
else
    record "L4" "egyezik" "nincs" "egyezik" "OK"
fi
step_end "L4 (Red-Team szkriptek == HEAD)"

summary
