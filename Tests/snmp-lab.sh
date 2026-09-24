#!/bin/bash
# Starts macOS's own net-snmp agent (/usr/sbin/snmpd, 5.6) on UDP 127.0.0.1:1161 and
# [::1]:1161 for the SNMP client tests:
#   v2c  community "public"
#   v3   user "lab", SHA / AES-128, auth "labpassword", priv "labprivpass" (authPriv)
#        user "labmd5", MD5 / DES, same passwords
# net-snmp 5.6 knows MD5/SHA-1 and DES/AES-128 only; SHA-2 and AES-192/256 are covered by the
# offline round-trip tests against SheepLog's own fake agent.
#
#   Tests/snmp-lab.sh          start (prints the PID and how to stop it)
#   Tests/snmp-lab.sh stop     stop a lab started earlier (waits until snmpd has exited)
#
# Every start wipes the lab's state, so snmpd comes up with a new random engine ID (what a
# replaced device looks like to a v3 client). SNMP_LAB_KEEP_STATE=1 keeps it: same engine ID,
# snmpEngineBoots + 1 (a rebooted device). SNMP_LAB_PORT picks another port (own state dir).
#
# Then (xcodebuild hands TEST_RUNNER_-prefixed variables to the tests without the prefix):
#   TEST_RUNNER_SHEEPLOG_SNMP_LAB=1 xcodebuild -project SheepLog.xcodeproj -scheme SheepLog \
#       -configuration Debug test -destination 'platform=macOS' -only-testing:SheepLogTests/LiveSNMPTests
set -euo pipefail

PORT="${SNMP_LAB_PORT:-1161}"
STATE="${TMPDIR:-/tmp}/sheeplog-snmp-lab-$PORT"   # per port: two labs must not share (and rm -rf) one directory
SNMPD=/usr/sbin/snmpd

if [[ "${1:-}" == "stop" ]]; then
    if [[ -f "$STATE/snmpd.pid" ]]; then
        PID="$(cat "$STATE/snmpd.pid")"
        if kill "$PID" 2>/dev/null; then
            # snmpd writes its persistent state (engine boots) on the way out: wait for it.
            for _ in $(seq 1 50); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
            echo "snmp-lab: stopped."
        else
            echo "snmp-lab: not running."
        fi
        rm -f "$STATE/snmpd.pid"
    else
        echo "snmp-lab: no PID file in $STATE."
    fi
    exit 0
fi

if [[ -f "$STATE/snmpd.pid" ]] && kill -0 "$(cat "$STATE/snmpd.pid")" 2>/dev/null; then
    echo "snmp-lab: already running (PID $(cat "$STATE/snmpd.pid")). Stop it with: $0 stop"
    exit 0
fi

if [[ "${SNMP_LAB_KEEP_STATE:-}" != "1" ]]; then
    rm -rf "$STATE"
fi
mkdir -p "$STATE/persist"

# macOS's snmpd is built without the VACM config tokens (rocommunity / rouser log "Unknown
# token" and access is open); they stay for other net-snmp builds. createUser has to be in the
# main file on this build (it is ignored in the persistent snmpd.conf). The persistent
# directory (engine ID, boots, localized user keys) lives in the temp dir, never in /var.
cat > "$STATE/snmpd.conf" <<EOF
agentaddress udp:127.0.0.1:$PORT,udp6:[::1]:$PORT
rocommunity public 127.0.0.1
rouser lab priv
sysLocation SheepLog snmp-lab
sysContact  lab@example.net
sysName     sheeplog-lab
createUser lab SHA "labpassword" AES "labprivpass"
createUser labmd5 MD5 "labpassword" DES "labprivpass"
EOF

export SNMP_PERSISTENT_DIR="$STATE/persist"
# -C skips every config file not named by -c — the persistent one (engine ID, boots) too, so
# SNMP_LAB_KEEP_STATE names it explicitly.
CONF="$STATE/snmpd.conf"
if [[ "${SNMP_LAB_KEEP_STATE:-}" == "1" && -f "$STATE/persist/snmpd.conf" ]]; then
    CONF="$CONF,$STATE/persist/snmpd.conf"
fi
"$SNMPD" -f -Lf "$STATE/snmpd.log" -C -c "$CONF" -r -p "$STATE/snmpd.pid" &
PID=$!
echo "$PID" > "$STATE/snmpd.pid"

for _ in $(seq 1 50); do
    if /usr/bin/snmpget -v2c -c public -t 0.3 -r 0 "127.0.0.1:$PORT" SNMPv2-MIB::sysDescr.0 >/dev/null 2>&1; then
        echo "snmp-lab: snmpd is answering on udp 127.0.0.1:$PORT (PID $PID)"
        echo "  v2c: community public"
        echo "  v3:  user lab, SHA/AES-128, auth labpassword, priv labprivpass"
        echo "       user labmd5, MD5/DES, same passwords"
        echo "  log: $STATE/snmpd.log"
        echo "  stop: $0 stop    (or: kill $PID)"
        exit 0
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "snmp-lab: snmpd exited — see $STATE/snmpd.log" >&2
        tail -20 "$STATE/snmpd.log" >&2 || true
        exit 1
    fi
    sleep 0.2
done
echo "snmp-lab: snmpd started (PID $PID) but does not answer — see $STATE/snmpd.log" >&2
exit 1
