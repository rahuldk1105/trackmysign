#!/usr/bin/env bash
# End-to-end test: virtual token + generated PDFs + independent validation.
# Needs: softhsm2, opensc (pkcs11-tool), qpdf, poppler-utils, openssl, python3 with pyhanko + reportlab.
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
vcheck() { python3 -W ignore "$ROOT/tests/verify_check.py" "$BIN" "$1" "$2" "${ROOTS[@]}" || fail=1; }
for f in plain rotated objstm form cropbox indirect broken presigned presigned-objstm presigned-form; do
  "$BIN" sign "$W/fx/$f.pdf" --out "$W/signed/$f.pdf" --reason Approved --location Chennai >/dev/null
  check "$W/fx/$f.pdf" "$W/signed/$f.pdf"
done
for p in 1 2 3 4; do
  "$BIN" sign "$W/fx/rotated.pdf" --page $p --out "$W/signed/rot$p.pdf" >/dev/null
  check "$W/fx/rotated.pdf" "$W/signed/rot$p.pdf"
done
image() { python3 -W ignore "$ROOT/tests/check_image.py" "$@" || fail=1; }
for img in sig.png sig-palette.png sig.jpg; do
  kind=${img##*.}
  for p in 1 2 3 4; do
    "$BIN" sign "$W/fx/rotated.pdf" --page $p --image "$W/fx/$img" --out "$W/signed/img-$img-$p.pdf" >/dev/null
    check "$W/fx/rotated.pdf" "$W/signed/img-$img-$p.pdf"
    image "$W/fx/rotated.pdf" "$W/signed/img-$img-$p.pdf" $p "$kind" left
  done
done
"$BIN" sign "$W/fx/presigned.pdf" --image "$W/fx/sig.png" --image-position above --out "$W/signed/img-above.pdf" >/dev/null
check "$W/fx/presigned.pdf" "$W/signed/img-above.pdf"
image "$W/fx/presigned.pdf" "$W/signed/img-above.pdf" 2 png above
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
# Batch: one token session for all files; a bad file is skipped, the rest signed.
mkdir -p "$W/batch"
for f in plain objstm presigned; do cp "$W/fx/$f.pdf" "$W/batch/"; done
printf 'not a pdf' > "$W/batch/bad.pdf"
if "$BIN" sign "$W/batch/plain.pdf" "$W/batch/bad.pdf" "$W/batch/objstm.pdf" "$W/batch/presigned.pdf" \
     --image "$W/fx/sig.png" >"$W/batch.out" 2>"$W/batch.err"; then
  echo "FAIL batch with a bad file reported success"; fail=1
fi
if grep -q "Failed: .*bad.pdf" "$W/batch.err" && [ "$(grep -c '^Signing as' "$W/batch.out")" = 1 ] \
   && [ "$(grep -c '^Signed:' "$W/batch.out")" = 3 ] && [ ! -e "$W/batch/bad_signed.pdf" ]; then
  echo "PASS batch skips the bad file"
else
  echo "FAIL batch: $(cat "$W/batch.out" "$W/batch.err")"; fail=1
fi
for f in plain objstm presigned; do check "$W/fx/$f.pdf" "$W/batch/${f}_signed.pdf"; done
for f in presigned presigned-objstm presigned-form; do vcheck "$W/fx/$f.pdf" valid; done
for f in plain objstm form broken presigned presigned-form rot2 invisible twice; do vcheck "$W/signed/$f.pdf" valid; done
for f in plain twice; do
  python3 -W ignore "$ROOT/tests/tamper.py" flip "$W/signed/$f.pdf" "$W/tampered-$f.pdf"
  vcheck "$W/tampered-$f.pdf" invalid
done
python3 -W ignore "$ROOT/tests/tamper.py" content "$W/signed/twice.pdf" "$W/changed.pdf"
vcheck "$W/changed.pdf" valid

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
# Image on every page (one shared image object), and a batch with pages + timestamp + LTV.
"$BIN" sign "$W/fx/rotated.pdf" --pages all --image "$W/fx/sig.png" --out "$W/signed/img-pages.pdf" >/dev/null
check "$W/fx/rotated.pdf" "$W/signed/img-pages.pdf"
for p in 1 2 3 4; do image "$W/fx/rotated.pdf" "$W/signed/img-pages.pdf" $p png left; done
mkdir -p "$W/batch-ltv"
for f in plain presigned-objstm; do cp "$W/fx/$f.pdf" "$W/batch-ltv/"; done
"$BIN" sign "$W/batch-ltv/plain.pdf" "$W/batch-ltv/presigned-objstm.pdf" --pages all --image "$W/fx/sig.jpg" \
  --timestamp "$TSA" --ltv >/dev/null || fail=1
for f in plain presigned-objstm; do check --timestamp --ltv "$W/fx/$f.pdf" "$W/batch-ltv/${f}_signed.pdf"; done
# Certification (DocMDP): each level, approvals after levels 2 and 3, refusals.
n=1
for lvl in none forms annotations; do
  "$BIN" sign "$W/fx/plain.pdf" --certify $lvl --out "$W/signed/cert-$lvl.pdf" >/dev/null
  check --certify=$n "$W/fx/plain.pdf" "$W/signed/cert-$lvl.pdf"
  vcheck "$W/signed/cert-$lvl.pdf" valid
  n=$((n + 1))
done
for f in objstm form indirect broken; do
  "$BIN" sign "$W/fx/$f.pdf" --certify forms --pages all --out "$W/signed/cert-$f.pdf" >/dev/null
  check --certify=2 "$W/fx/$f.pdf" "$W/signed/cert-$f.pdf"
done
for lvl in forms annotations; do
  n=$([ $lvl = forms ] && echo 2 || echo 3)
  "$BIN" sign "$W/signed/cert-$lvl.pdf" --position top-left --image "$W/fx/sig.png" --out "$W/signed/cert-$lvl-approved.pdf" >/dev/null
  check --certify=$n "$W/signed/cert-$lvl.pdf" "$W/signed/cert-$lvl-approved.pdf"
  vcheck "$W/signed/cert-$lvl-approved.pdf" valid
done
"$BIN" sign "$W/signed/cert-objstm.pdf" --position top-left --out "$W/signed/cert-objstm-approved.pdf" >/dev/null
check --certify=2 "$W/signed/cert-objstm.pdf" "$W/signed/cert-objstm-approved.pdf"
# Visible approvals pass as in Acrobat (above); invisible ones even pyHanko's stricter default.
"$BIN" sign "$W/signed/cert-forms.pdf" --invisible --out "$W/signed/cert-forms-invisible.pdf" >/dev/null
check --certify=2 --strict "$W/signed/cert-forms.pdf" "$W/signed/cert-forms-invisible.pdf"
"$BIN" sign "$W/fx/plain.pdf" --certify none --timestamp "$TSA" --ltv --out "$W/signed/cert-ltv.pdf" >/dev/null
check --certify=1 --timestamp --ltv "$W/fx/plain.pdf" "$W/signed/cert-ltv.pdf"
refused() {
  if "$BIN" sign "$1" "${@:3}" --out "$W/refused.pdf" >"$W/out" 2>"$W/err"; then
    echo "FAIL signed $1 although it should be refused"; fail=1
  elif grep -q "$2" "$W/err" && ! grep -q "^Signing as" "$W/out" && [ ! -e "$W/refused.pdf" ]; then
    echo "PASS refused: $(basename "$1") ${*:3}"
  else
    echo "FAIL refusal of $1: $(cat "$W/out" "$W/err")"; fail=1
  fi
}
refused "$W/signed/cert-none.pdf" "no changes allowed"
refused "$W/signed/cert-none.pdf" "no changes allowed" --invisible
refused "$W/fx/presigned.pdf" "Only the first signature can certify" --certify forms
refused "$W/signed/cert-forms.pdf" "Only the first signature can certify" --certify annotations
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
