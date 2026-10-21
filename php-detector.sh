#!/usr/bin/env bash
#
# php-detector.sh - inventory of every PHP process on this server.
#
# For each PHP process it answers three questions:
#   1. Does it run on the host, or inside a container?
#   2. If it is in a container: which one (name / id / image)?
#   3. Which PHP version is it running? (so you can spot builds that still
#      need the emergency upstream patch)
#
# Detection is done from /proc, so it is exact rather than a guess based on
# the ps output:
#
#   /proc/<pid>/cgroup  The container id is embedded in the cgroup path on
#                       both cgroup v1 and v2:
#                         docker:  /system.slice/docker-<id>.scope   (v2)
#                                  /docker/<id>                      (v1)
#                         k8s:     .../cri-containerd-<id>.scope
#                         podman:  .../libpod-<id>.scope
#                       -> works as a normal user, no privileges needed
#
#   /proc/<pid>/status  "NSpid:" has more than one value when the process
#                       lives in a PID namespace, i.e. it is containerised.
#
#   /proc/<pid>/ns/pid  The PID-namespace inode. It is compared against the
#                       namespace of every container's init process, which
#                       gives an exact match (needs root for processes owned
#                       by other users).
#
#   /proc/<pid>/cgroup  For host processes it also yields the systemd unit,
#                       so the script can print the exact command needed to
#                       restart that PHP (systemctl restart <unit>).
#
# Usage:  ./php-detector.sh [options]      (see --help)
#
set -uo pipefail

PROG=${0##*/}

# ---------------------------------------------------------------- options ---
JSON=0
VERSIONS=1
SUMMARY_ONLY=0
MIN_VERSION=""
PACKAGES=0
WATCH=0
USE_COLOR=0

usage() {
    cat <<EOF
$PROG - find every PHP process on this server and show where it runs
         (host, or which container).

USAGE
  $PROG [options]

OPTIONS
  -s, --summary          Only print the per-location summary table.
  -v, --versions         Probe PHP versions (default).
      --no-versions      Skip version probing (fastest; no docker exec).
  -m, --min-version V    Flag every PHP older than V (e.g. 7.4.33) as
                         "OUTDATED" - useful right after an emergency patch.
  -p, --packages         Also list installed host PHP packages (dpkg).
  -j, --json             Machine readable output.
  -w, --watch [SEC]      Re-run the scan every SEC seconds (default 5).
  -h, --help             This help.

EXAMPLES
  $PROG                        # full inventory with PHP versions
  $PROG -m 8.3.10              # flag PHP builds older than 8.3.10
  $PROG --json | jq .          # feed the result into other tooling
  sudo $PROG                   # root sees every process, incl. other users'
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--summary)     SUMMARY_ONLY=1 ;;
        -v|--versions)    VERSIONS=1 ;;
        --no-versions)    VERSIONS=0 ;;
        -m|--min-version) MIN_VERSION="${2:-}"; shift ;;
        -p|--packages)    PACKAGES=1 ;;
        -j|--json)        JSON=1 ;;
        -w|--watch)       WATCH=5; [[ ${2:-} =~ ^[0-9]+$ ]] && { WATCH=$2; shift; } ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [[ -t 1 && $JSON -eq 0 ]]; then USE_COLOR=1; fi

if [[ -n $MIN_VERSION && ! $MIN_VERSION =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    echo "invalid --min-version: $MIN_VERSION" >&2
    exit 2
fi

# ------------------------------------------------------------------ colors --
C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GRN=''; C_YEL=''; C_CYN=''
if [[ $USE_COLOR -eq 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_CYN=$'\033[36m'
fi

# ------------------------------------------------------- container registry --
# C_ENGINE[id]=docker|podman, C_NAME, C_IMAGE, C_STATE, C_INITPID, C_NS
declare -A C_ENGINE=() C_NAME=() C_IMAGE=() C_STATE=() C_INITPID=() C_NS=()
declare -A NS_TO_CID=()          # pid-namespace inode -> container id

load_containers() {
    local engine ids id name image state pid ns
    for engine in docker podman; do
        command -v "$engine" >/dev/null 2>&1 || continue
        case $engine in
            docker) ids=$(docker ps -aq 2>/dev/null) ;;
            podman) ids=$(podman ps -aq 2>/dev/null) ;;
        esac
        [[ -z $ids ]] && continue
        # One inspect call for all containers: id|name|image|state|initpid
        # shellcheck disable=SC2086
        while IFS='|' read -r id name image state pid; do
            [[ -z ${id:-} ]] && continue
            name=${name#/}
            C_ENGINE[$id]=$engine
            C_NAME[$id]=$name
            C_IMAGE[$id]=$image
            C_STATE[$id]=$state
            if [[ $pid =~ ^[1-9][0-9]*$ ]]; then
                C_INITPID[$id]=$pid
                ns=$(readlink "/proc/$pid/ns/pid" 2>/dev/null)
                if [[ -n $ns ]]; then
                    C_NS[$id]=$ns
                    NS_TO_CID[$ns]=$id
                fi
            fi
        done < <("$engine" inspect \
                    -f '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.State.Pid}}' \
                    $ids 2>/dev/null)
    done
}

# ------------------------------------------------------- helper: cgroup id ---
# Pull the container id out of a cgroup path.
cgroup_cid() {
    local cg=$1
    local re='(docker|moby|libpod|nerdctl|cri-containerd|containerd|crio|cri-o)[-/]([0-9a-f]{12,64})'
    if [[ $cg =~ $re ]]; then
        printf '%s' "${BASH_REMATCH[2]}"
        return 0
    fi
    return 1
}

# ------------------------------------------------------- helper: php check ---
is_php() {
    local comm=$1 argv0=$2
    [[ $comm == php* ]] && return 0
    # php-fpm rewrites argv[0] to "php-fpm: master process (...)"
    argv0=${argv0%%:*}
    [[ ${argv0##*/} == php* ]] && return 0
    return 1
}

php_role() {
    local comm=$1 cmd=$2
    if [[ $cmd == *"master process"* ]]; then
        echo "fpm-master"
    elif [[ $cmd == *"pool"* ]]; then
        echo "fpm-worker"
    elif [[ $cmd == *composer* ]]; then
        echo "composer"
    elif [[ $comm == *"fpm"* || $comm == *"cgi"* ]]; then
        echo "fpm"
    else
        echo "cli"
    fi
}

host_unit() {
    local cg=$1
    if [[ $cg =~ ([^/[:space:]]+)\.service ]]; then
        printf '%s.service' "${BASH_REMATCH[1]}"
    elif [[ $cg =~ ([^/[:space:]]+)\.scope ]]; then
        printf '%s.scope' "${BASH_REMATCH[1]}"
    else
        printf 'host'
    fi
}

# ------------------------------------------------------- version probing ----
parse_php_ver() {
    # "PHP 8.3.6 (fpm-fcgi) ..." -> 8.3.6
    grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' <<<"$1" | head -1 | awk '{print $2}'
}

container_exec() {
    local engine=$1 cid=$2; shift 2
    case $engine in
        podman) timeout 15 podman exec "$cid" "$@" 2>/dev/null ;;
        *)     timeout 15 docker exec "$cid" "$@" 2>/dev/null ;;
    esac
}

# probe a binary that exists in the host filesystem
host_bin_ver() {
    local bin=$1
    [[ -z $bin || ! -x $bin ]] && return 1
    local out v
    out=$(timeout 5 "$bin" -v 2>/dev/null | head -1)
    v=$(parse_php_ver "$out")
    [[ -n $v ]] && { printf '%s' "$v"; return 0; }
    return 1
}

# probe a binary that exists inside a container
container_bin_ver() {
    local engine=$1 cid=$2 bin=$3
    [[ -z $bin ]] && return 1
    local out v
    out=$(container_exec "$engine" "$cid" "$bin" -v | head -1)
    v=$(parse_php_ver "$out")
    [[ -n $v ]] && { printf '%s' "$v"; return 0; }
    return 1
}

# probe a binary that lives in another process' filesystem (works for
# containers that docker exec cannot reach, as long as we may read /proc/<pid>)
version_via_proc_root() {
    local pid=$1 exe=$2
    [[ -z $pid || -z $exe ]] && return 1
    local path="/proc/$pid/root$exe"
    [[ -x $path ]] || return 1
    local out v
    out=$(timeout 5 "$path" -v 2>/dev/null | head -1)
    v=$(parse_php_ver "$out")
    [[ -n $v ]] && { printf '%s' "$v"; return 0; }
    return 1
}

# exact version of an installed host package series, e.g. php8.3-fpm -> 8.3.6
pkg_series_ver() {
    local series=$1 pkg out
    for pkg in "php${series}-fpm" "php${series}-cli" "php${series}-common"; do
        out=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null) || continue
        out=${out%%-*}                     # 8.3.6-2ubuntu8 -> 8.3.6
        [[ $out =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && { printf '%s' "$out"; return 0; }
    done
    return 1
}

# --------------------------------------------------------- version compare ---
# returns 0 when $1 (have) is older than $2 (want)
version_lt() {
    local have=$1 want=$2
    [[ -z $have || -z $want ]] && return 1
    [[ "$have" == "$want" ]] && return 1
    local lowest
    lowest=$(printf '%s\n%s\n' "$have" "$want" | sort -V | head -1)
    [[ $lowest == "$have" ]]
}

# ------------------------------------------------------------------- scan ---
declare -a P_PID=() P_USER=() P_ROLE=() P_VER=() P_LOC=() P_ENGINE=()
declare -a P_IMAGE=() P_CMD=() P_UNIT=() P_CID=() P_OWNER=() P_OUTDATED=()
declare -a P_STATE=() P_KEY=() P_EXE=()
declare -A UID_NAME=()

# per-location aggregates
declare -A LOC_ENGINE=() LOC_IMAGE=() LOC_VER=() LOC_COUNT=() LOC_UNIT=()
declare -A LOC_PIDS=() LOC_CID=() LOC_STATE=() LOC_NAME=() LOC_EXES=() LOC_CMD=()
declare -A LOC_PID1=()

resolve_uid() {
    local uid=$1
    [[ -n ${UID_NAME[$uid]:-} ]] && { printf '%s' "${UID_NAME[$uid]}"; return; }
    local name
    name=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
    [[ -z $name ]] && name="uid:$uid"
    UID_NAME[$uid]=$name
    printf '%s' "$name"
}

scan() {
    local d pid comm cmdline argv0 exe cg uid ns_depth line cid ns
    local key engine name image state loc unit role ver user outdated
    local -a argv

    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [[ $pid == "$$" ]] && continue
        read -r comm 2>/dev/null < "$d/comm" || continue
        mapfile -d '' -t argv 2>/dev/null < "$d/cmdline"
        argv0=${argv[0]:-}
        cmdline="${argv[*]}"
        is_php "$comm" "$argv0" || continue

        cg=""
        while IFS= read -r line; do cg+="$line "; done 2>/dev/null < "$d/cgroup"

        uid=""; ns_depth=1; proc_state=""
        while read -r k v1 v2 v3 v4; do
            case $k in
                Uid:)   uid=${v1:-} ;;
                NSpid:) [[ -n ${v2:-} ]] && ns_depth=2 ;;
                State:) proc_state=${v1:-} ;;
            esac
        done 2>/dev/null < "$d/status"
        # a zombie/exiting php is not a running php
        case $proc_state in
            Z*|X*) continue ;;
        esac

        # --- which container (if any)? ---
        cid=$(cgroup_cid "$cg")
        if [[ -z $cid ]]; then
            ns=$(readlink "$d/ns/pid" 2>/dev/null)
            [[ -n $ns && -n ${NS_TO_CID[$ns]:-} ]] && cid=${NS_TO_CID[$ns]}
        fi

        exe=$(readlink "$d/exe" 2>/dev/null)
        exe=${exe% (deleted)}
        role=$(php_role "$comm" "$cmdline")
        user=$(resolve_uid "${uid:-0}")

        if [[ -n $cid ]]; then
            engine=${C_ENGINE[$cid]:-unknown}
            name=${C_NAME[$cid]:-$cid}
            image=${C_IMAGE[$cid]:-}
            state=${C_STATE[$cid]:-}
            unit=""
            key="$engine:$name"
            loc="$engine:$name"
        else
            if [[ $ns_depth -gt 1 ]]; then
                # in a PID namespace but the container could not be named
                engine="unknown"; name="?"; image=""; state=""; unit=""
                key="container:unknown"; loc="container:unknown"
            else
                engine="host"; name="host"; image=""; state=""
                unit=$(host_unit "$cg")
                key="host:$unit"; loc="host"
            fi
        fi

        P_PID+=("$pid");     P_USER+=("$user");   P_ROLE+=("$role")
        P_VER+=("");         P_LOC+=("$loc");     P_ENGINE+=("$engine")
        P_IMAGE+=("$image"); P_CMD+=("$cmdline"); P_UNIT+=("$unit")
        P_CID+=("$cid");     P_OWNER+=("$name");  P_OUTDATED+=("0")
        P_STATE+=("$state"); P_KEY+=("$key");     P_EXE+=("$exe")
    done
}

# ------------------------------------------------------- version per site ---
probe_versions() {
    local key engine cid name image unit cmd exes exe v series
    for key in "${!LOC_COUNT[@]}"; do
        engine=${LOC_ENGINE[$key]}
        cid=${LOC_CID[$key]}
        v=""
        if [[ $engine == host ]]; then
            exes=${LOC_EXES[$key]:-}
            for exe in $exes; do
                v=$(host_bin_ver "$exe") && break
            done
            if [[ -z $v ]]; then
                # derive the series from the config path, then from the packages
                cmd=${LOC_CMD[$key]:-}
                if [[ $cmd =~ /etc/php/([0-9]+\.[0-9]+) ]]; then
                    series=${BASH_REMATCH[1]}
                    for exe in "/usr/sbin/php-fpm${series}" "/usr/bin/php${series}" \
                                "/usr/sbin/php-fpm" "/usr/bin/php"; do
                        v=$(host_bin_ver "$exe") && break
                    done
                    [[ -z $v ]] && v=$(pkg_series_ver "$series")
                fi
            fi
        elif [[ $engine == unknown ]]; then
            # containerised but not attributable to a known engine: try to run
            # the binary through the process' own filesystem
            exes=${LOC_EXES[$key]:-}
            for exe in $exes; do
                v=$(version_via_proc_root "${LOC_PID1[$key]:-}" "$exe") && break
            done
        else
            exes=${LOC_EXES[$key]:-}
            for exe in $exes; do
                v=$(container_bin_ver "$engine" "$cid" "$exe") && break
            done
            if [[ -z $v ]]; then
                for exe in /usr/local/bin/php /usr/bin/php /usr/local/bin/php8.3 \
                           /usr/bin/php8.3 /usr/local/bin/php8 /usr/local/bin/php7.4 \
                           /usr/bin/php7.4 /usr/sbin/php-fpm; do
                    v=$(container_bin_ver "$engine" "$cid" "$exe") && break
                done
            fi
            if [[ -z $v ]]; then
                v=$(parse_php_ver "$(container_exec "$engine" "$cid" sh -c 'php -v 2>/dev/null | head -1')")
            fi
            if [[ -z $v ]]; then
                for exe in $exes; do
                    v=$(version_via_proc_root "${LOC_PID1[$key]:-}" "$exe") && break
                done
            fi
        fi
        [[ -z $v ]] && v="unknown"
        LOC_VER[$key]=$v
    done
}

# ---------------------------------------------------------------- output ----
json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\r'/}
    s=${s//$'\n'/ }
    printf '%s' "$s"
}

print_json() {
    local i total=${#P_PID[@]}
    printf '{\n  "host": "%s",\n  "generated_at": "%s",\n' \
        "$(hostname)" "$(date '+%Y-%m-%d %H:%M:%S%z')"
    printf '  "min_version": "%s",\n' "$MIN_VERSION"
    printf '  "processes": [\n'
    for ((i = 0; i < total; i++)); do
        printf '    {'
        printf '"pid": %s, ' "${P_PID[$i]}"
        printf '"user": "%s", ' "$(json_escape "${P_USER[$i]}")"
        printf '"role": "%s", ' "$(json_escape "${P_ROLE[$i]}")"
        printf '"php_version": "%s", ' "$(json_escape "${P_VER[$i]}")"
        printf '"location": "%s", ' "$(json_escape "${P_LOC[$i]}")"
        printf '"engine": "%s", ' "$(json_escape "${P_ENGINE[$i]}")"
        printf '"container_id": "%s", ' "$(json_escape "${P_CID[$i]}")"
        printf '"container_name": "%s", ' "$(json_escape "${P_OWNER[$i]}")"
        printf '"image": "%s", ' "$(json_escape "${P_IMAGE[$i]}")"
        printf '"unit": "%s", ' "$(json_escape "${P_UNIT[$i]}")"
        printf '"outdated": %s, ' "$([[ ${P_OUTDATED[$i]} -eq 1 ]] && echo true || echo false)"
        printf '"cmdline": "%s"}' "$(json_escape "${P_CMD[$i]}")"
        [[ $i -lt $((total - 1)) ]] && printf ','
        printf '\n'
    done
    printf '  ]\n}\n'
}

build_summary() {
    local i loc
    LOC_ENGINE=(); LOC_IMAGE=(); LOC_VER=(); LOC_COUNT=(); LOC_UNIT=()
    LOC_PIDS=(); LOC_CID=(); LOC_STATE=(); LOC_NAME=(); LOC_EXES=(); LOC_CMD=(); LOC_PID1=()
    for ((i = 0; i < ${#P_PID[@]}; i++)); do
        loc=${P_KEY[$i]}
        LOC_COUNT[$loc]=$(( ${LOC_COUNT[$loc]:-0} + 1 ))
        LOC_PIDS[$loc]="${LOC_PIDS[$loc]:-}${P_PID[$i]} "
        LOC_PID1[$loc]="${LOC_PID1[$loc]:-${P_PID[$i]}}"
        LOC_ENGINE[$loc]=${P_ENGINE[$i]}
        LOC_IMAGE[$loc]=${P_IMAGE[$i]}
        LOC_STATE[$loc]=${P_STATE[$i]}
        LOC_CID[$loc]=${P_CID[$i]}
        LOC_NAME[$loc]=${P_OWNER[$i]}
        LOC_UNIT[$loc]=${P_UNIT[$i]}
        LOC_CMD[$loc]="${LOC_CMD[$loc]:-}${P_CMD[$i]} "
        LOC_VER[$loc]="n/a"
        [[ -n ${P_EXE[$i]} ]] && LOC_EXES[$loc]="${LOC_EXES[$loc]:-}${P_EXE[$i]} "
    done
}

print_report() {
    local total=${#P_PID[@]}
    local host_name; host_name=$(hostname)
    local i loc detail vers img unit eng cid

    printf '%sPHP PROCESS INVENTORY%s  %s  %s\n' \
        "$C_BOLD" "$C_RESET" "$host_name" "$(date '+%Y-%m-%d %H:%M:%S')"

    if [[ $total -eq 0 ]]; then
        printf '%sNo PHP processes found.%s\n' "$C_DIM" "$C_RESET"
        return
    fi

    # ---- summary table -------------------------------------------------
    printf '\n%s%-26s %-8s %-36s %-12s %5s  %s%s\n' \
        "$C_BOLD" "LOCATION" "ENGINE" "IMAGE / SYSTEMD UNIT" "PHP" "PROCS" "PIDS" "$C_RESET"
    for loc in "${!LOC_COUNT[@]}"; do
        vers=${LOC_VER[$loc]}; img=${LOC_IMAGE[$loc]}; unit=${LOC_UNIT[$loc]}
        if [[ -n $img ]]; then
            detail=$img
            if [[ -n ${LOC_STATE[$loc]} && ${LOC_STATE[$loc]} != running ]]; then
                detail="${img} (${LOC_STATE[$loc]})"
            fi
        else
            detail=$unit
        fi
        printf '%-26s %-8s %-36s %-12s %5s  %s\n' \
            "$loc" "${LOC_ENGINE[$loc]}" "${detail:0:36}" "${vers:0:12}" \
            "${LOC_COUNT[$loc]}" "${LOC_PIDS[$loc]:0:46}"
    done

    # ---- per process detail --------------------------------------------
    if [[ $SUMMARY_ONLY -eq 0 ]]; then
        printf '\n%s%-8s %-10s %-11s %-12s %-24s %s%s\n' \
            "$C_BOLD" "PID" "USER" "ROLE" "PHP" "LOCATION" "COMMAND" "$C_RESET"
        for ((i = 0; i < total; i++)); do
            local flag=""
            [[ ${P_OUTDATED[$i]} -eq 1 ]] && flag=" <= OUTDATED"
            local cmd=${P_CMD[$i]}
            printf '%-8s %-10s %-11s %-12s %-24s %s%s\n' \
                "${P_PID[$i]}" "${P_USER[$i]}" "${P_ROLE[$i]}" "${P_VER[$i]:-n/a}" \
                "${P_KEY[$i]}" "${cmd:0:110}" "$flag"
        done
    fi

    # ---- what to restart -------------------------------------------------
    printf '\n%sRESTART COMMANDS%s\n' "$C_BOLD" "$C_RESET"
    for loc in "${!LOC_COUNT[@]}"; do
        eng=${LOC_ENGINE[$loc]}; unit=${LOC_UNIT[$loc]}; cid=${LOC_CID[$loc]}
        if [[ $eng == host ]]; then
            if [[ $unit == *.service ]]; then
                printf '  %-26s systemctl restart %s\n' "$loc" "$unit"
            else
                printf '  %-26s # not a systemd service - restart manually\n' "$loc"
            fi
        elif [[ $eng == unknown ]]; then
            printf '  %-26s # container could not be identified\n' "$loc"
        else
            printf '  %-26s %s restart %s\n' "$loc" "$eng" "${cid:-${LOC_NAME[$loc]}}"
        fi
    done

    # ---- min version summary --------------------------------------------
    if [[ -n $MIN_VERSION ]]; then
        local old=0
        for ((i = 0; i < total; i++)); do [[ ${P_OUTDATED[$i]} -eq 1 ]] && old=$((old + 1)); done
        if [[ $old -eq 0 ]]; then
            printf '\nAll detected PHP are >= %s\n' "$MIN_VERSION"
        else
            printf '\n%s%d process(es) running PHP older than %s%s\n' \
                "$C_RED" "$old" "$MIN_VERSION" "$C_RESET"
        fi
    fi

    # ---- host packages ----------------------------------------------------
    if [[ $PACKAGES -eq 1 ]]; then
        printf '\n%sINSTALLED HOST PHP PACKAGES%s\n' "$C_BOLD" "$C_RESET"
        dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php*' 2>/dev/null \
            | awk '$1 ~ /^ii/ {printf "  %-24s %s\n", $2, $3}' | sort
    fi
}

run_once() {
    P_PID=(); P_USER=(); P_ROLE=(); P_VER=(); P_LOC=(); P_ENGINE=()
    P_IMAGE=(); P_CMD=(); P_UNIT=(); P_CID=(); P_OWNER=(); P_OUTDATED=()
    P_STATE=(); P_KEY=(); P_EXE=()
    scan
    build_summary
    if [[ $VERSIONS -eq 1 ]]; then probe_versions; fi
    # copy the per-location version onto every process, flag outdated ones
    local i
    for ((i = 0; i < ${#P_PID[@]}; i++)); do
        P_VER[$i]=${LOC_VER[${P_KEY[$i]}]:-unknown}
        if [[ -n $MIN_VERSION && ${P_VER[$i]} != unknown ]]; then
            version_lt "${P_VER[$i]}" "$MIN_VERSION" && P_OUTDATED[$i]=1
        fi
    done
    if [[ $JSON -eq 1 ]]; then print_json; else print_report; fi
}

main() {
    load_containers
    if [[ $WATCH -gt 0 ]]; then
        while true; do
            if [[ -t 1 ]]; then printf '\033[H\033[2J'; fi
            run_once
            sleep "$WATCH"
        done
    else
        run_once
    fi
}

main "$@"
