#!/usr/bin/env bash
# deploy_red_team_scripts.sh -- EGYSZERI, KULON JOVAHAGYANDO lepes (M2b).
# A Red-Team-VM-en levo, kampanykori attack_runner.py (fe59748) helyere a
# HEAD-valtozatot teszi. A ketto kozott csak a T0846/T0888 cimkek ternek el
# (AST-azonos, lasd docs/tdk/ELTERESNAPLO.md E-04).
#
# Hasznalat:
#   bash scripts/deploy_red_team_scripts.sh            # vegrehajtas (megerosites kell)
#   bash scripts/deploy_red_team_scripts.sh --dry-run  # csak kiirja a parancsokat
#   bash scripts/deploy_red_team_scripts.sh --yes      # interaktiv IGEN nelkul (a jovahagyas mashol tortent)
#
# Lepesek:
#   1. a VM-en levo fajl hash-e: ha mar a HEAD-del egyezik -> nincs teendo;
#      ha sem a fe59748-cal, sem a HEAD-del nem egyezik -> megall.
#   2. mentes: attack_runner.py.fe59748.bak (meglevo .bak-ot nem ir felul,
#      csak ellenorzi a hash-et).
#   3. a HEAD-valtozat (git show HEAD:scripts/attack_runner.py) scp-vel
#      .new neven felmegy, hash-ellenorzes, majd mv a helyere, chmod 755.
#   4. vegso sha256-ellenorzes.
# Nem telepit csomagot, nem futtatja a szkriptet, mas fajlt nem erint.

set -euo pipefail

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --yes) ASSUME_YES=1 ;;
        *) echo "Ismeretlen kapcsolo: $arg (--dry-run, --yes)" >&2; exit 64 ;;
    esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$REPO/results/deploy-red-team-$(date -u +%Y%m%dT%H%M%SZ).log"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
HOST="redteam"
F="attack_runner.py"
DST="/home/ot/$F"
BAK="$DST.<vm-sha>.bak"   # a VM aktualis sha-jabol szamoljuk (lasd lent)
NEW="$DST.new"
OLD_SHA="16d267c16d7487b7d4fa4b24002a4590624a2c4554c5306c0ac445bc6ad621ad"   # fe59748:scripts/attack_runner.py (eredeti augusztusi baseline)

mkdir -p "$REPO/results"
exec > >(tee -a "$LOG") 2>&1

log() { echo "[$(date -u +%FT%TZ)] $*"; }
die() { log "HIBA: $*"; exit 1; }

run() {
    if (( DRY_RUN )); then
        printf '[DRY-RUN]'; printf ' %q' "$@"; printf '\n'
        return 0
    fi
    "$@"
}
remote_sha() {
    ssh "${SSH_OPTS[@]}" "$HOST" "sha256sum $1 2>/dev/null" | cut -d' ' -f1
}

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
git -C "$REPO" show "HEAD:scripts/$F" > "$TMP"
HEAD_SHA=$(sha256sum < "$TMP" | cut -d' ' -f1)
log "HEAD:scripts/$F sha256=$HEAD_SHA"
log "fe59748 (eredeti baseline) sha256=$OLD_SHA"

# Ismert korabbi allapotok: a scripts/$F MINDEN korabban committolt blobjanak
# sha256-ja. A deploy csak akkor ir felul, ha a VM-en egy ilyen (azaz egy
# korabbi, verziozott) valtozat van -- ismeretlen (nem committolt) allapotot
# sosem bant. Igy egy koztes HEAD (pl. a 2026-10-29-i deploy) is biztonsagosan
# frissitheto a jelenlegi HEAD-re.
declare -A KNOWN_SHAS
while read -r c; do
    [[ -n $c ]] || continue
    s=$(git -C "$REPO" show "$c:scripts/$F" 2>/dev/null | sha256sum | cut -d' ' -f1) || continue
    [[ -n $s ]] && KNOWN_SHAS[$s]="$c"
done < <(git -C "$REPO" log --all --format=%H -- "scripts/$F")
log "ismert korabbi committolt blobok szama: ${#KNOWN_SHAS[@]}"

if (( DRY_RUN )); then
    run ssh "${SSH_OPTS[@]}" "$HOST" "sha256sum $DST"
    run ssh "${SSH_OPTS[@]}" "$HOST" "test -e $BAK || cp -p $DST $BAK"
    run ssh "${SSH_OPTS[@]}" "$HOST" "sha256sum $BAK"
    run scp "${SSH_OPTS[@]}" "$TMP" "$HOST:$NEW"
    run ssh "${SSH_OPTS[@]}" "$HOST" "sha256sum $NEW"
    run ssh "${SSH_OPTS[@]}" "$HOST" "mv -f $NEW $DST && chmod 755 $DST"
    run ssh "${SSH_OPTS[@]}" "$HOST" "sha256sum $DST"
    log "dry-run vege, semmi nem valtozott"
    exit 0
fi

# 1. kiindulo allapot
cur=$(remote_sha "$DST") || die "a $HOST:$DST nem olvashato"
log "VM $DST sha256=$cur"
if [[ $cur == "$HEAD_SHA" ]]; then
    log "a VM-en mar a HEAD-valtozat van, nincs teendo"
    exit 0
fi
[[ -n ${KNOWN_SHAS[$cur]:-} ]] \
    || die "a VM-en levo fajl egyetlen committolt verziove sem egyezik ($cur) -- kezi vizsgalat kell"
log "a VM ismert, korabban committolt allapotban van: commit ${KNOWN_SHAS[$cur]}"
BAK="$DST.${cur:0:12}.bak"
log "mentes neve: $BAK"

if (( ASSUME_YES )); then
    log "--yes: a jovahagyas a parancssorbol jott, nincs interaktiv kerdes"
else
    read -r -p "A $HOST:$DST lecserelese a HEAD-valtozatra. Folytatod? (IGEN/nem) " answer </dev/tty
    [[ $answer == "IGEN" ]] || die "megszakitva a felhasznalo altal"
fi

# 2. mentes (meglevo .bak-ot nem irunk felul)
ssh "${SSH_OPTS[@]}" "$HOST" "test -e $BAK || cp -p $DST $BAK"
bak=$(remote_sha "$BAK") || die "a mentes ($BAK) nem olvashato"
[[ $bak == "$cur" ]] || die "a mentes ($BAK) hash-e nem a VM aktualis fajljae: $bak != $cur"
log "mentes rendben: $BAK sha256=$bak"

# 3. feltoltes .new neven, ellenorzes, majd csere
scp "${SSH_OPTS[@]}" "$TMP" "$HOST:$NEW"
new=$(remote_sha "$NEW") || die "a feltoltott $NEW nem olvashato"
[[ $new == "$HEAD_SHA" ]] || die "a feltoltott $NEW hash-e elter: $new (a regi fajl erintetlen)"
ssh "${SSH_OPTS[@]}" "$HOST" "mv -f $NEW $DST && chmod 755 $DST"

# 4. vegso ellenorzes
fin=$(remote_sha "$DST") || die "a csere utan a $DST nem olvashato"
[[ $fin == "$HEAD_SHA" ]] || die "a csere utan a $DST hash-e elter: $fin"
log "KESZ: $HOST:$DST sha256=$fin (== HEAD); mentes: $BAK"
