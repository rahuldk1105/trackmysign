#!/usr/bin/env bash
# End-to-end test: virtual token + generated PDFs + independent validation.
# Needs: softhsm2, opensc (pkcs11-tool), qpdf, openssl, python3 with pyhanko + reportlab.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=${WORK:-$(mktemp -d)}
BIN=${TRACKMYSIGN_BIN:-$ROOT/target/debug/trackmysign}
eval "$("$ROOT/tests/make-test-token.sh" "$W/token")"
python3 "$ROOT/tests/make_fixtures.py" "$W/fx" >/dev/null
mkdir -p "$W/signed"
ROOTS=("$TEST_PKI/root.pem" "$W/fx/auditor-pki/ca.pem")
fail=0
check() { python3 -W ignore "$ROOT/tests/validate.py" "$1" "$2" "${ROOTS[@]}" || fail=1; }
for f in plain rotated objstm form cropbox indirect broken presigned presigned-objstm presigned-form; do
  "$BIN" sign "$W/fx/$f.pdf" --out "$W/signed/$f.pdf" --reason Approved --location Chennai >/dev/null
  check "$W/fx/$f.pdf" "$W/signed/$f.pdf"
done
for p in 1 2 3 4; do
  "$BIN" sign "$W/fx/rotated.pdf" --page $p --out "$W/signed/rot$p.pdf" >/dev/null
  check "$W/fx/rotated.pdf" "$W/signed/rot$p.pdf"
done
# One signature, a widget on each selected page: name, sig count, --pages, expected pages.
pages() {
  "$BIN" sign "$W/fx/$1.pdf" --pages "$3" "${@:5}" --reason Approved --out "$W/signed/$1-pages.pdf" >/dev/null
  check "$W/fx/$1.pdf" "$W/signed/$1-pages.pdf"
  python3 -W ignore "$ROOT/tests/check_pages.py" "$W/signed/$1-pages.pdf" "$2" $4 || fail=1
}
pages rotated 1 all "1 2 3 4"
pages mixed 1 all "1 2 3 4 5"
pages plain 1 1 "1" --position top-left
pages indirect 1 all "1"
pages objstm 1 all "1 2"
pages presigned 2 all "1 2"
pages presigned-form 2 1 "1"
"$BIN" sign "$W/fx/mixed.pdf" --pages 1-2,4 --page 2 --rect 20,30,150,50 --out "$W/signed/mixed-some.pdf" >/dev/null
check "$W/fx/mixed.pdf" "$W/signed/mixed-some.pdf"
python3 -W ignore "$ROOT/tests/check_pages.py" "$W/signed/mixed-some.pdf" 1 1 2 4 || fail=1
"$BIN" sign "$W/signed/presigned-pages.pdf" --pages 2,1 --position top-right --out "$W/signed/pages-twice.pdf" >/dev/null
check "$W/signed/presigned-pages.pdf" "$W/signed/pages-twice.pdf"
python3 -W ignore "$ROOT/tests/check_pages.py" "$W/signed/pages-twice.pdf" 3 1 2 || fail=1
"$BIN" sign "$W/fx/presigned.pdf" --invisible --out "$W/signed/invisible.pdf" >/dev/null
check "$W/fx/presigned.pdf" "$W/signed/invisible.pdf"
"$BIN" sign "$W/signed/presigned.pdf" --position top-left --out "$W/signed/twice.pdf" >/dev/null
check "$W/signed/presigned.pdf" "$W/signed/twice.pdf"
if TRACKMYSIGN_PIN=00000000 "$BIN" sign "$W/fx/plain.pdf" --out "$W/x.pdf" 2>"$W/err"; then
  echo "FAIL wrong PIN accepted"; fail=1
else
  grep -q "Wrong PIN" "$W/err" && echo "PASS wrong PIN rejected" || { echo "FAIL: $(cat "$W/err")"; fail=1; }
fi
# A driver that fails to load must not hide the token behind another one.
: > "$W/broken-pkcs11.so"
if TRACKMYSIGN_PKCS11_MODULE="$W/broken-pkcs11.so:$TRACKMYSIGN_PKCS11_MODULE" "$BIN" certs >"$W/certs" 2>&1 \
  && grep -q "not loaded" "$W/certs" && grep -q "RAHUL TEST DIRECTOR" "$W/certs"; then
  echo "PASS broken driver skipped"
else
  echo "FAIL broken driver: $(cat "$W/certs")"; fail=1
fi
[ $fail = 0 ] && echo "ALL PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
