#!/usr/bin/env bash
# run_campaign.sh -- validacios kampany vezenylo + adatgyujtes (M4d, D6, prereg-v1.1).
#
# A LAPTOP Git Bash-ebol fut, a ~/.ssh/config host-aliasait hasznalva
# (sensor, redteam; mint a lab_up.sh). Az attack_runner.py es a
# benign_generator.py a Red-Team-VM-en, levalasztva (setsid/nohup) fut, igy a
# laptop-SSH megszakadasa nem allitja le a kampanyt. A begyujtes kulon lepes,
# utolag is futtathato: `--collect <kampany-ID>`.
#
# Hasznalat:
#   OPENPLC_USER=... OPENPLC_PASS=... bash scripts/run_campaign.sh --campaign V1 --seed 1
#   bash scripts/run_campaign.sh --collect campaign_20261101T120000Z_V1_s1
#   bash scripts/run_campaign.sh --campaign V1 --seed 1 --dry-run
#
# A hitelesito adat (OPENPLC_USER/OPENPLC_PASS) a laptop kornyezeti valtozoibol
# jon, es az ssh STDIN-jen jut a redteamra (NEM parancssori argumentum, NEM
# fajl, NEM log). Ha nincs beallitva: a szkript indulas elott hibaval leall.
#
# D6 artefaktumok: data/<kampany-ID>/ alatt
#   capture.pcap, eve_slice.json, capture_loss.log, attack_log.jsonl,
#   attack_schedule.jsonl, attack_control.jsonl, benign_log.jsonl, *_stdout.log,
#   window.txt, manifest.json.  A pcap NEM kerul gitbe (.gitignore).

set -euo pipefail

CAMPAIGN="V1"
SEED=""
DRY_RUN=0
COLLECT_ID=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --campaign) CAMPAIGN="${2:-}"; shift 2 ;;
        --seed) SEED="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --collect) COLLECT_ID="${2:-}"; shift 2 ;;
        *) echo "Ismeretlen kapcsolo: $1 (--campaign V1|V2, --seed N, --dry-run, --collect ID)" >&2; exit 64 ;;
    esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
REDTEAM_DIR="/home/ot"
SENSOR_IF="${OT_SENSOR_IF:-enp0s8}"
EVE_JSON="${OT_EVE_JSON:-/var/log/suricata/eve.json}"
CAPTURE_LOSS="${OT_CAPTURE_LOSS:-/opt/zeek/spool/zeek/capture_loss.log}"

ts() { date -u +%FT%TZ; }
log() { echo "[$(ts)] $*"; }

rsh() {  # dry-run: csak kiir; eles: vegrehajt
    local host=$1; shift
    if (( DRY_RUN )); then printf '[DRY-RUN] ssh %s %s %q\n' "${SSH_OPTS[*]}" "$host" "$*"; return 0; fi
    ssh "${SSH_OPTS[@]}" "$host" "$*"
}
rcp() {
    local src=$1 dst=$2
    if (( DRY_RUN )); then printf '[DRY-RUN] scp %s %s %s\n' "${SSH_OPTS[*]}" "$src" "$dst"; return 0; fi
    scp "${SSH_OPTS[@]}" "$src" "$dst"
}

# ------------------------------------------------------------------ preflight
# E-32: indulas ELOTT, ha a redteamon barmilyen attack_runner.py / benign_generator.py
# fut, vagy a sensoron otcap_* tcpdump fut -> HIBA (exit 5), semmit nem inditunk.
# E-34: a jelolteket pgrep -f adja (cmdline-ra illeszt), de CSAK a python- (ill.
# tcpdump-) argv[0]-u folyamatok szamitanak (/proc/<pid>/cmdline), hogy a bent
# maradt indito bash -c (argv[0]=bash, de a cmdline-jaban ott a szkriptnevek)
# NE okozzon hamis exit 5-ot -- ugyanaz a /proc-logika, mint E-33-ban.
preflight_clean_or_die() {
    if (( DRY_RUN )); then
        printf '[DRY-RUN] preflight: redteam attack_runner/benign_generator + sensor otcap_* tcpdump ellenorzes (ha barmi fut -> exit 5)\n'
        return 0
    fi
    local rt sn
    rt=$(ssh "${SSH_OPTS[@]}" redteam '
        for p in $(pgrep -f "attack_runner\.py|benign_generator\.py" 2>/dev/null); do
            [ -r /proc/$p/cmdline ] || continue
            a0=$(tr "\0" "\n" < /proc/$p/cmdline | head -1)
            case "$a0" in *python*) printf "pid=%s " "$p"; tr "\0" " " < /proc/$p/cmdline; echo ;; esac
        done' || true)
    sn=$(ssh "${SSH_OPTS[@]}" sensor '
        for p in $(pgrep -f "otcap_" 2>/dev/null); do
            [ -r /proc/$p/cmdline ] || continue
            a0=$(tr "\0" "\n" < /proc/$p/cmdline | head -1)
            case "$a0" in *tcpdump*) printf "pid=%s " "$p"; tr "\0" " " < /proc/$p/cmdline; echo ;; esac
        done' || true)
    if [[ -n "$rt" || -n "$sn" ]]; then
        echo "HIBA (exit 5): mar fut kampany-folyamat -- semmit nem inditok (E-32)." >&2
        [[ -n "$rt" ]] && { echo "  redteam attack/benign:" >&2; printf '    %s\n' "$rt" >&2; }
        [[ -n "$sn" ]] && { echo "  sensor otcap tcpdump:" >&2; printf '    %s\n' "$sn" >&2; }
        echo "  Elobb allitsd le ezeket (es gyujtsd be --collect-tel), majd indits ujra." >&2
        exit 5
    fi
    log "preflight: tiszta (nincs futo attack_runner/benign a redteamon, nincs otcap tcpdump a sensoron)"
}

# ------------------------------------------------------------------ indit
start_campaign() {
    local id=$1 camp=$2 seed=$3
    local rtdir="$REDTEAM_DIR/results/campaigns/$id"
    local rpcap="/tmp/otcap_$id.pcap"

    # hitelesito adat ellenorzese MIELOTT barmit inditunk
    if (( ! DRY_RUN )); then
        [[ -n "${OPENPLC_USER:-}" && -n "${OPENPLC_PASS:-}" ]] \
            || { echo "HIBA: OPENPLC_USER/OPENPLC_PASS nincs beallitva -- a kampany nem indul." >&2; exit 3; }
    fi

    log "1) pcap inditasa a Sensoron (leválasztva): $rpcap (if=$SENSOR_IF)"
    rsh sensor "sudo -n sh -c 'setsid tcpdump -i $SENSOR_IF -w $rpcap -U </dev/null >/dev/null 2>&1 & echo \$! > /tmp/otcap_$id.pid'"

    log "2) benign_generator.py (.51) inditasa + ELLENORZES, majd csak akkor attack_runner.py (leválasztva), creds az STDIN-en"
    # A tavoli parancs argv-jeben NINCS titok (csak ID/CAMP/SEED); a creds az STDIN ket soran jon.
    # E-29 javitas: a benign eloszor indul; ha 5 s utan nem el, a szkript KILEP (exit 4),
    # es az attack_runner NEM indul el. A benign_log.jsonl a kampany-dirbe kerul (cwd),
    # a benign.pid abszolut utra irodik.
    # E-33 javitas: NINCS "sh -c ... exec python3" burok es NINCS "pgrep ... | head -1".
    # Oka: a benignt futtato bash -c vezenylo cmdline-ja maga is tartalmazza a
    # "benign_generator.py" szot, ezert a regi pgrep|head-1 a vezenylo pid-jet adta,
    # nem a tenyleges pythonet. Most a benign kozvetlenul (setsid nohup python3) indul,
    # cwd=RTDIR, es a pid-et a /proc/<pid>/cmdline argv[0]=python ellenorzessel
    # valasztjuk ki (a bash -c vezenylo argv[0]=bash, igy kiesik).
    local remote='
        IFS= read -r u; IFS= read -r p
        [ -n "$u" ] && [ -n "$p" ] || { echo "NO_CREDS" >&2; exit 3; }
        export OPENPLC_USER="$u" OPENPLC_PASS="$p"
        export OT_PLC_MGMT_SSH_KEY="$HOME/.ssh/id_ed25519_effect" GATES_PRECONFIRMED=1
        cd "$HOME" && mkdir -p "$RTDIR"
        ( cd "$RTDIR" && setsid nohup python3 "$HOME/benign_generator.py" </dev/null >"$RTDIR/benign_stdout.log" 2>&1 & ) </dev/null >/dev/null 2>&1
        sleep 5
        bpid=""
        for cand in $(pgrep -f benign_generator.py 2>/dev/null); do
            [ -r "/proc/$cand/cmdline" ] || continue
            a0=$(tr "\0" "\n" < "/proc/$cand/cmdline" | head -1)
            case "$a0" in *python*) bpid="$cand"; break ;; esac
        done
        if [ -z "$bpid" ]; then
            echo "BENIGN_FAILED -- a benign_generator 5 s utan nem fut (python argv[0] nincs); az attack_runner NEM indul" >&2
            tail -n 20 "$RTDIR/benign_stdout.log" >&2 2>/dev/null
            exit 4
        fi
        echo "$bpid" > "$RTDIR/benign.pid"
        export ATTACK_LOG_PATH="$RTDIR/attack_log.jsonl"
        export ATTACK_SCHEDULE_PATH="$RTDIR/attack_schedule.jsonl"
        export ATTACK_CONTROL_PATH="$RTDIR/attack_control.jsonl"
        setsid nohup python3 "$HOME/attack_runner.py" --campaign "$CAMP" --seed "$SEED" </dev/null >"$RTDIR/attack_stdout.log" 2>&1 &
        echo $! > "$RTDIR/attack.pid"
        echo "LAUNCHED attack_pid=$(cat "$RTDIR/attack.pid") benign_pid=$bpid"
        # E-34: az indito bash -c explicit kilep, hogy ne maradjon bent; a
        # hatterfolyamatok teljesen levalasztva (stdin/stdout/stderr atiranyitva).
        exit 0
    '
    if (( DRY_RUN )); then
        printf '[DRY-RUN] ssh %s redteam RTDIR=%q CAMP=%q SEED=%q bash -c <remote: read creds/STDIN; benign indit (setsid nohup python3, NINCS sh -c) +5s ellenorzes (/proc argv[0]=python); ha nem el -> exit 4, attack NEM indul; kulonben attack indit>\n' \
            "${SSH_OPTS[*]}" "$rtdir" "$camp" "$seed"
        printf '[DRY-RUN]   (creds a laptop OPENPLC_USER/OPENPLC_PASS-bol, az ssh STDIN ket soran)\n'
    else
        if ! printf '%s\n%s\n' "$OPENPLC_USER" "$OPENPLC_PASS" \
            | ssh "${SSH_OPTS[@]}" redteam "RTDIR=$rtdir CAMP=$camp SEED=$seed bash -c '$remote'"; then
            echo "HIBA: a kampany inditasa sikertelen (a benign nem indult, vagy SSH-hiba) -- az attack_runner nem indult el." >&2
            exit 4
        fi
    fi
    log "   a kampany a redteamon fut; a laptop-SSH megszakadasa nem allitja le."
}

# ------------------------------------------------------------------ var
wait_campaign() {
    local id=$1
    local rtdir="$REDTEAM_DIR/results/campaigns/$id"
    if (( DRY_RUN )); then printf '[DRY-RUN] poll: timeout 60 ssh redteam "kill -0 $(cat %s/attack.pid) -> ALIVE/GONE" (ServerAlive; max 10 sikertelen poll utan begyujtes)\n' "$rtdir"; return 0; fi
    log "3) varakozas a kampany befejezesere (poll 60 s, ServerAlive, sikertelen poll ujraprobal)"
    local pid; pid=$(timeout 30 ssh "${SSH_OPTS[@]}" redteam "cat $rtdir/attack.pid" 2>/dev/null || true)
    [[ -n "$pid" ]] || { log "FIGYELEM: nincs attack.pid -- ugrunk a begyujtesre"; return 0; }
    # E-36: a poll nem akadhat el. Minden ssh timeout 60 alatt + ServerAlive; a remote
    # ALIVE/GONE-t echoz (kill -0). Sikertelen (ures) poll -> ujraprobal; 10 egymast
    # koveto sikertelen poll utan begyujtessel kilepunk (nem akadunk el orokre).
    local fails=0 st
    while true; do
        st=$(timeout 60 ssh "${SSH_OPTS[@]}" redteam "kill -0 $pid 2>/dev/null && echo ALIVE || echo GONE" 2>/dev/null || true)
        if [[ "$st" == *GONE* ]]; then
            log "   az attack_runner (pid=$pid) befejezodott"; break
        elif [[ "$st" == *ALIVE* ]]; then
            fails=0; sleep 60
        else
            fails=$((fails+1))
            log "   FIGYELEM: sikertelen poll ($fails/10) -- ujraprobalas"
            (( fails >= 10 )) && { log "   10 egymast koveto sikertelen poll -- begyujtessel kilepunk"; break; }
            sleep 6
        fi
    done
}

# ------------------------------------------------------------------ begyujt
collect_campaign() {
    local id=$1
    local rtdir="$REDTEAM_DIR/results/campaigns/$id"
    local rpcap="/tmp/otcap_$id.pcap"
    local outdir="$REPO/data/$id"
    log "4) leallitas + begyujtes -> $outdir"
    # E-36: a kampany-dir letezzen MIELOTT a benign_stop_verified.txt-t irjuk (a mkdir
    # korabban a benign-blokk UTAN volt -> "No such file or directory" a begyujteskor).
    (( DRY_RUN )) || mkdir -p "$outdir"

    # E-32/E-33: a SAJAT kampany benignjenek (pid-fajl) leallitasa pid alapjan, UTANA
    # az OSSZES benign_generator.py megszunesenek ellenorzese (ps -C python3, nincs
    # pgrep-onmatch). Ha marad, azt is leallitjuk es naplozzuk. A vegeredmeny
    # (benign_stop_verified=true/false) a manifestbe kerul.
    if (( DRY_RUN )); then
        printf '[DRY-RUN] redteam: benign.pid (pid alapu) leallitas + utolagos ps -C python3 ellenorzes (maradek leallitasa); benign_stop_verified -> manifest\n'
    else
        local bstop
        bstop=$(ssh "${SSH_OPTS[@]}" redteam "
            pf=$rtdir/benign.pid
            if [ -f \"\$pf\" ]; then
                bp=\$(cat \"\$pf\"); kill -INT \"\$bp\" 2>/dev/null
                for i in 1 2 3 4 5; do kill -0 \"\$bp\" 2>/dev/null || break; sleep 1; done
                if kill -0 \"\$bp\" 2>/dev/null; then kill -KILL \"\$bp\" 2>/dev/null; sleep 1; fi
                kill -0 \"\$bp\" 2>/dev/null && echo \"FIGYELEM: sajat benign \$bp meg el\" || echo \"sajat benign \$bp leallt\"
            else echo '(nincs benign.pid)'; fi
            rem=\$(ps -C python3 -o pid=,cmd= | grep benign_generator.py | grep -v grep || true)
            if [ -n \"\$rem\" ]; then
                echo 'MARADEK benign_generator (leallitas):'; printf '  %s\n' \"\$rem\"
                echo \"\$rem\" | awk '{print \$1}' | while read -r p; do kill -TERM \"\$p\" 2>/dev/null; done
                sleep 3
                ps -C python3 -o pid=,cmd= | grep benign_generator.py | grep -v grep | awk '{print \$1}' | while read -r p; do kill -KILL \"\$p\" 2>/dev/null; done
                sleep 1
            fi
            rem2=\$(ps -C python3 -o pid=,cmd= | grep benign_generator.py | grep -v grep || true)
            [ -z \"\$rem2\" ] && echo 'benign_stop_verified=true' || { echo 'benign_stop_verified=false'; echo \"MEG FUT: \$rem2\"; }
        ")
        printf '%s\n' "$bstop"
        if echo "$bstop" | grep -q 'benign_stop_verified=true'; then
            echo true > "$outdir/benign_stop_verified.txt"
        else
            echo false > "$outdir/benign_stop_verified.txt"
        fi
    fi
    # a SAJAT kampany pcap-jenek (otcap pid-fajl) leallitasa + ellenorzes (tcpdump root -> sudo -n).
    rsh sensor  "pf=/tmp/otcap_$id.pid; if [ -f \"\$pf\" ]; then tp=\$(cat \"\$pf\"); sudo -n kill -INT \"\$tp\" 2>/dev/null; for i in 1 2 3 4 5; do sudo -n kill -0 \"\$tp\" 2>/dev/null || break; sleep 1; done; if sudo -n kill -0 \"\$tp\" 2>/dev/null; then sudo -n kill -KILL \"\$tp\" 2>/dev/null; sleep 1; fi; sudo -n kill -0 \"\$tp\" 2>/dev/null && echo \"FIGYELEM: tcpdump \$tp meg el\" || echo \"tcpdump \$tp leallt\"; else echo '(nincs otcap pid)'; fi"
    (( DRY_RUN )) || sleep 2

    if (( DRY_RUN )); then
        printf '[DRY-RUN] mkdir -p %s\n' "$outdir"
    else
        mkdir -p "$outdir"
    fi

    # redteam artefaktumok
    for f in attack_log.jsonl attack_schedule.jsonl attack_control.jsonl attack_stdout.log \
             benign_log.jsonl benign_stdout.log; do
        rcp "redteam:$rtdir/$f" "$outdir/$f" || log "FIGYELEM: nem sikerult: $f"
    done
    # pcap
    rcp "sensor:$rpcap" "$outdir/capture.pcap" || log "FIGYELEM: pcap nem sikerult"

    # 5) kampanyablak VM-idobol: a begyujtott JSONL-ek elso/utolso ts-e -60 s/+60 s
    if (( DRY_RUN )); then
        printf '[DRY-RUN] window.txt szamitasa VM-idobol (attack_control + attack_log ts, -60s/+60s)\n'
        printf '[DRY-RUN] eve_slice.json: ssh sensor python3 (errors="replace") a window-ra\n'
        printf '[DRY-RUN] capture_loss.log: tail\n'
        printf '[DRY-RUN] manifest.json: sha256, scriptek git+sha, seed, campaign, window(VM-ido), laptop_date_u(info), kizart ablakok\n'
        log "DRY-RUN vege -- semmi nem valtozott a VM-eken."
        return 0
    fi

    local win
    win=$(python3 - "$outdir" <<'PY'
import json,sys,datetime as dt,os
outdir=sys.argv[1]
ts=[]
for fn in ("attack_control.jsonl","attack_log.jsonl"):
    p=os.path.join(outdir,fn)
    if not os.path.exists(p): continue
    for line in open(p,encoding="utf-8",errors="replace"):
        line=line.strip()
        if not line: continue
        try: r=json.loads(line)
        except: continue
        for k in ("ts","start_ts","end_ts"):
            if k in r and r[k]:
                try: ts.append(dt.datetime.fromisoformat(r[k]));
                except: pass
if not ts:
    print("NOWINDOW"); sys.exit(0)
w0=(min(ts)-dt.timedelta(seconds=60))
w1=(max(ts)+dt.timedelta(seconds=60))
print(w0.isoformat()); print(w1.isoformat())
PY
)
    local w0 w1
    w0=$(echo "$win" | sed -n '1p'); w1=$(echo "$win" | sed -n '2p')
    if [[ "$w0" == "NOWINDOW" || -z "$w0" ]]; then
        log "FIGYELEM: a VM-ido-ablak nem szamithato (nincs ts) -- az eve-szelet kimarad"
    else
        {
          echo "kampanyablak (VM-ido, D6; a JSONL-ek ts-ebol, -60s/+60s)"
          echo "window_start: $w0"
          echo "window_end:   $w1"
          echo "laptop_date_u (csak tajekoztato): $(date -u +%FT%TZ)"
        } > "$outdir/window.txt"
        # 5b) eve-szelet python-nal (errors='replace'), jq nelkul
        ssh "${SSH_OPTS[@]}" sensor "sudo -n python3 - '$w0' '$w1' '$EVE_JSON'" > "$outdir/eve_slice.json" <<'PY' || log "FIGYELEM: eve_slice sikertelen"
import json,sys
w0,w1,path=sys.argv[1],sys.argv[2],sys.argv[3]
for line in open(path,encoding="utf-8",errors="replace"):
    line=line.strip()
    if not line or line[0]!="{": continue
    try: r=json.loads(line)
    except: continue
    t=r.get("timestamp","").replace("+0000","+00:00")
    if w0<=t<=w1: sys.stdout.write(json.dumps(r,ensure_ascii=False)+"\n")
PY
    fi

    rsh sensor "tail -n 500 $CAPTURE_LOSS 2>/dev/null || echo '(nincs capture_loss.log)'" > "$outdir/capture_loss.log" || true

    # 6) manifest
    local git_head; git_head=$(git -C "$REPO" rev-parse HEAD)
    python3 - "$outdir" "$id" "$git_head" "$REPO" "$(date -u +%FT%TZ)" <<'PY'
import hashlib,json,os,subprocess,sys,datetime
outdir,cid,git_head,repo,laptop_now=sys.argv[1:6]
def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(1<<20),b""): h.update(c)
    return h.hexdigest()
files={}
for n in sorted(os.listdir(outdir)):
    p=os.path.join(outdir,n)
    if os.path.isfile(p) and n not in ("manifest.json","benign_stop_verified.txt"):
        files[n]={"sha256":sha(p),"bytes":os.path.getsize(p)}
bsv=None
bp=os.path.join(outdir,"benign_stop_verified.txt")
if os.path.exists(bp):
    bsv=open(bp,encoding="utf-8").read().strip()=="true"
scripts={}
for s in ("attack_runner.py","benign_generator.py","run_campaign.sh","evaluate_campaign.py"):
    try:
        blob=subprocess.check_output(["git","-C",repo,"show",f"HEAD:scripts/{s}"])
        scripts[s]={"git_commit":git_head,"sha256":hashlib.sha256(blob).hexdigest()}
    except subprocess.CalledProcessError:
        scripts[s]={"git_commit":git_head,"sha256":None}
excluded=[]; win={}
wp=os.path.join(outdir,"window.txt")
if os.path.exists(wp):
    for line in open(wp,encoding="utf-8"):
        if line.startswith("window_start:"): win["start_vm"]=line.split(":",1)[1].strip()
        if line.startswith("window_end:"): win["end_vm"]=line.split(":",1)[1].strip()
cp=os.path.join(outdir,"attack_control.jsonl")
if os.path.exists(cp):
    for line in open(cp,encoding="utf-8",errors="replace"):
        line=line.strip()
        if not line: continue
        try: r=json.loads(line)
        except: continue
        if r.get("kind") in ("init_baseline","restore_plc"):
            excluded.append({"kind":r["kind"],"episode_id":r.get("episode_id"),"ts":r.get("ts")})
man={"campaign_id":cid,"git_head":git_head,"window_vm_time":win,
     "laptop_date_u_info_only":laptop_now,"excluded_windows":excluded,
     "benign_stop_verified":bsv,
     "scripts":scripts,"files":files,
     "generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}
json.dump(man,open(os.path.join(outdir,"manifest.json"),"w",encoding="utf-8"),ensure_ascii=False,indent=2)
print(f"manifest.json kesz: {len(files)} fajl, {len(excluded)} kizart ablak, window={win}")
PY
    rm -f "$outdir/benign_stop_verified.txt"
    log "begyujtes kesz -- $outdir"
}

# ------------------------------------------------------------------ fo
if [[ -n "$COLLECT_ID" ]]; then
    log "run_campaign.sh --collect $COLLECT_ID"
    collect_campaign "$COLLECT_ID"
    exit 0
fi

case "$CAMPAIGN" in V1|V2) ;; *) echo "A --campaign csak V1 vagy V2 lehet." >&2; exit 64 ;; esac
[[ "$SEED" =~ ^[0-9]+$ ]] || { echo "A --seed kotelezo es egesz szam." >&2; exit 64; }
TS_UTC="$(date -u +%Y%m%dT%H%M%SZ)"
CAMPAIGN_ID="campaign_${TS_UTC}_${CAMPAIGN}_s${SEED}"
log "run_campaign.sh: campaign=$CAMPAIGN seed=$SEED id=$CAMPAIGN_ID dry-run=$DRY_RUN"

preflight_clean_or_die
start_campaign "$CAMPAIGN_ID" "$CAMPAIGN" "$SEED"
wait_campaign "$CAMPAIGN_ID"
collect_campaign "$CAMPAIGN_ID"
log "run_campaign.sh vege -- $CAMPAIGN_ID"
