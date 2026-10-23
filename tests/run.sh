#!/usr/bin/env bash
# End-to-end test: virtual token + generated PDFs + independent validation.
# Needs: softhsm2, opensc (pkcs11-tool), qpdf, openssl, python3 with pyhanko + reportlab.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=${WORK:-$(mktemp -d)}
BIN=${TRACKMYSIGN_BIN:-$ROOT/target/debug/trackmysign}
# Local TSA / OCSP / CRL server for the timestamp and LTV tests (no internet needed).
PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
export TEST_SERVICES_URL=http://127.0.0.1:$PORT
eval "$("$ROOT/tests/make-test-token.sh" "$W/token")"
python3 "$ROOT/tests/services.py" "$TEST_PKI" "$PORT" &
SVC_PID=$!
trap 'kill $SVC_PID 2>/dev/null' EXIT
for _ in $(seq 50); do curl -sf "$TEST_SERVICES_URL/root.der" -o /dev/null && break; sleep 0.1; done
python3 "$ROOT/tests/make_fixtures.py" "$W/fx" >/dev/null
mkdir -p "$W/signed"
ROOTS=("$TEST_PKI/root.pem" "$W/fx/auditor-pki/ca.pem")
fail=0
check() { python3 -W ignore "$ROOT/tests/validate.py" "$@" "${ROOTS[@]}" || fail=1; }
for f in plain rotated objstm form cropbox indirect broken presigned presigned-objstm presigned-form; do
  "$BIN" sign "$W/fx/$f.pdf" --out "$W/signed/$f.pdf" --reason Approved --location Chennai >/dev/null
  check "$W/fx/$f.pdf" "$W/signed/$f.pdf"
done
for p in 1 2 3 4; do
  "$BIN" sign "$W/fx/rotated.pdf" --page $p --out "$W/signed/rot$p.pdf" >/dev/null
  check "$W/fx/rotated.pdf" "$W/signed/rot$p.pdf"
done
"$BIN" sign "$W/fx/presigned.pdf" --invisible --out "$W/signed/invisible.pdf" >/dev/null
check "$W/fx/presigned.pdf" "$W/signed/invisible.pdf"
"$BIN" sign "$W/signed/presigned.pdf" --position top-left --out "$W/signed/twice.pdf" >/dev/null
check "$W/signed/presigned.pdf" "$W/signed/twice.pdf"
# Trusted timestamp, and LTV (TSA CA only reachable via AIA, revocation via OCSP and CRLs).
TSA=$TEST_SERVICES_URL/tsa
"$BIN" sign "$W/fx/plain.pdf" --timestamp "$TSA" --out "$W/signed/ts.pdf" >/dev/null
check --timestamp "$W/fx/plain.pdf" "$W/signed/ts.pdf"
"$BIN" sign "$W/fx/plain.pdf" --timestamp "$TSA-nochain" --ltv --out "$W/signed/ltv.pdf" >/dev/null
check --timestamp --ltv "$W/fx/plain.pdf" "$W/signed/ltv.pdf"
"$BIN" sign "$W/fx/presigned-objstm.pdf" --timestamp "$TSA" --ltv --out "$W/signed/ltv-presigned.pdf" >/dev/null
check --timestamp --ltv "$W/fx/presigned-objstm.pdf" "$W/signed/ltv-presigned.pdf"
"$BIN" sign "$W/signed/ltv.pdf" --position top-left --timestamp "$TSA" --ltv --out "$W/signed/ltv-twice.pdf" >/dev/null
check --timestamp --ltv "$W/signed/ltv.pdf" "$W/signed/ltv-twice.pdf"
"$BIN" sign "$W/fx/broken.pdf" --ltv --out "$W/signed/ltv-only.pdf" >/dev/null
check --ltv "$W/fx/broken.pdf" "$W/signed/ltv-only.pdf"
if "$BIN" sign "$W/fx/plain.pdf" --timestamp http://127.0.0.1:1/tsa --out "$W/ts-down.pdf" 2>"$W/err"; then
  echo "FAIL signed although the TSA is unreachable"; fail=1
elif grep -q "Timestamp failed" "$W/err" && [ ! -e "$W/ts-down.pdf" ]; then
  echo "PASS unreachable TSA reported, nothing saved"
else
  echo "FAIL: $(cat "$W/err")"; fail=1
fi
if TRACKMYSIGN_PIN=00000000 "$BIN" sign "$W/fx/plain.pdf" --out "$W/x.pdf" 2>"$W/err"; then
  echo "FAIL wrong PIN accepted"; fail=1
else
  grep -q "Wrong PIN" "$W/err" && echo "PASS wrong PIN rejected" || { echo "FAIL: $(cat "$W/err")"; fail=1; }
fi
[ $fail = 0 ] && echo "ALL PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
