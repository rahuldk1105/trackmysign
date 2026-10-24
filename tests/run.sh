#!/usr/bin/env bash
# End-to-end test: virtual token + generated PDFs + independent validation.
# Needs: softhsm2, opensc (pkcs11-tool), qpdf, poppler-utils, openssl, node, python3 with pyhanko + reportlab.
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
# Signing into existing empty signature fields: original, field, output, check_field.py options.
field() {
  "$BIN" sign "$1" --field "$2" --reason Approved --out "$W/signed/$3.pdf" >/dev/null
  check "$1" "$W/signed/$3.pdf"
  python3 -W ignore "$ROOT/tests/check_field.py" "${@:4}" "$1" "$W/signed/$3.pdf" "$2" "${ROOTS[@]}" || fail=1
}
field "$W/fx/field-simple.pdf" ClientSignature field-simple --rotate 0
field "$W/fx/field-mixed.pdf" Director field-mixed
field "$W/fx/field-nested.pdf" approvals.director field-nested
field "$W/fx/field-rotated.pdf" Rotated90 field-rot90 --rotate 90
field "$W/signed/field-rot90.pdf" Rotated270 field-rot270 --rotate 270
field "$W/fx/field-lock.pdf" Approver field-lock --lock company
field "$W/fx/field-sv.pdf" CadesOnly field-cades --subfilter ETSI.CAdES.detached
"$BIN" sign "$W/fx/field-simple.pdf" --field ClientSignature --image "$W/fx/sig.png" --out "$W/signed/field-img.pdf" >/dev/null
check "$W/fx/field-simple.pdf" "$W/signed/field-img.pdf"
if "$BIN" info "$W/fx/field-nested.pdf" | grep "approvals.director: page 1, 340,692,200,60" >/dev/null \
   && "$BIN" info "$W/fx/field-rotated.pdf" | grep "Rotated90: page 1, 560,60,200,60" >/dev/null \
   && "$BIN" info "$W/fx/field-mixed.pdf" | grep "Existing signatures: 1" >/dev/null \
   && ! "$BIN" info "$W/signed/field-mixed.pdf" | grep "Empty signature fields" >/dev/null; then
  echo "PASS info lists empty signature fields"
else
  echo "FAIL info: $("$BIN" info "$W/fx/field-nested.pdf")"; fail=1
fi
# Refused: a seed value the signature cannot meet, a signed field, a missing one.
field_refused() {
  if "$BIN" sign "$W/fx/$1.pdf" --field "$2" --out "$W/refused.pdf" 2>"$W/err" >/dev/null; then
    echo "FAIL signed into $1 / $2"; fail=1
  elif grep -q "$3" "$W/err" && [ ! -e "$W/refused.pdf" ]; then
    echo "PASS $1 / $2 refused"
  else
    echo "FAIL: $(cat "$W/err")"; fail=1
  fi
}
field_refused field-sv Sha512Only "requires the digest sha512"
field_refused field-mixed Auditor "empty fields: Director"
field_refused field-simple Nope "empty fields: ClientSignature"
for f in field-simple field-mixed field-nested field-rot270 field-lock field-cades; do vcheck "$W/signed/$f.pdf" valid; done
for f in presigned presigned-objstm presigned-form; do vcheck "$W/fx/$f.pdf" valid; done
for f in plain objstm form broken presigned presigned-form rot2 invisible twice; do vcheck "$W/signed/$f.pdf" valid; done
for f in plain twice; do
  python3 -W ignore "$ROOT/tests/tamper.py" flip "$W/signed/$f.pdf" "$W/tampered-$f.pdf"
  vcheck "$W/tampered-$f.pdf" invalid
done
python3 -W ignore "$ROOT/tests/tamper.py" content "$W/signed/twice.pdf" "$W/changed.pdf"
vcheck "$W/changed.pdf" valid

# Password-protected PDFs: name and password ("" = empty user password, opens silently).
encsign() {
  local f=$1 pw=$2; shift 2
  local arg=(); [ -n "$pw" ] && arg=(--password "$pw")
  "$BIN" sign "$W/fx/$f.pdf" "${arg[@]}" "$@" --reason Approved --out "$W/signed/$f.pdf" >/dev/null
  check --password="$pw" "$W/fx/$f.pdf" "$W/signed/$f.pdf"
  python3 -W ignore "$ROOT/tests/verify_check.py" --password="$pw" "$BIN" "$W/signed/$f.pdf" valid "${ROOTS[@]}" || fail=1
}
encsign enc-rc40 ""
encsign enc-rc128 user
encsign enc-aes128 "" --pages all --image "$W/fx/sig.png"
encsign enc-aes128-meta user
encsign enc-aes256 own
encsign enc-aes256-r5 ""
encsign presigned-enc-aes256 user
encsign presigned-enc-rc128 own --invisible
encsign enc-restricted own
expect_fail() {
  local what=$1 pattern=$2; shift 2
  if "$@" --out "$W/x.pdf" >/dev/null 2>"$W/err" </dev/null; then
    echo "FAIL $what: signed"; fail=1
  elif grep -q "$pattern" "$W/err" && [ ! -e "$W/x.pdf" ]; then
    echo "PASS $what"
  else
    echo "FAIL $what: $(cat "$W/err")"; fail=1
  fi
}
expect_fail "restricted PDF refused without the owner password" "do not allow signing" \
  "$BIN" sign "$W/fx/enc-restricted.pdf"
expect_fail "wrong PDF password rejected" "password is not correct" \
  "$BIN" sign "$W/fx/enc-aes256.pdf" --password nope
expect_fail "missing PDF password reported" "password-protected" \
  "$BIN" sign "$W/fx/enc-rc128.pdf"
"$BIN" sign "$W/signed/enc-aes256.pdf" --password user --position top-left --out "$W/signed/enc-twice.pdf" >/dev/null
check --password=user "$W/signed/enc-aes256.pdf" "$W/signed/enc-twice.pdf"

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
"$BIN" sign "$W/fx/enc-aes256.pdf" --password user --timestamp "$TSA" --ltv --out "$W/signed/ltv-enc.pdf" >/dev/null
check --timestamp --ltv --password=user "$W/fx/enc-aes256.pdf" "$W/signed/ltv-enc.pdf"
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
# Certifying an encrypted PDF: /Perms and /Reference go into the encrypted update.
for f in enc-aes256:user enc-rc128:user enc-aes128:; do
  name=${f%%:*} pw=${f#*:}
  "$BIN" sign "$W/fx/$name.pdf" --password "$pw" --certify forms --out "$W/signed/cert-$name.pdf" >/dev/null
  check --certify=2 --password="$pw" "$W/fx/$name.pdf" "$W/signed/cert-$name.pdf"
  python3 -W ignore "$ROOT/tests/verify_check.py" --password="$pw" "$BIN" "$W/signed/cert-$name.pdf" valid "${ROOTS[@]}" || fail=1
done
"$BIN" sign "$W/signed/cert-enc-aes256.pdf" --password user --position top-left --out "$W/signed/cert-enc-approved.pdf" >/dev/null
check --certify=2 --password=user "$W/signed/cert-enc-aes256.pdf" "$W/signed/cert-enc-approved.pdf"
# Empty signature fields in an encrypted PDF (the field's /V and appearance go into
# the encrypted update), and certifying into a field that has a /Lock.
"$BIN" sign "$W/fx/field-enc.pdf" --password user --field approvals.director --out "$W/signed/field-enc.pdf" >/dev/null
check --password=user "$W/fx/field-enc.pdf" "$W/signed/field-enc.pdf"
python3 -W ignore "$ROOT/tests/check_field.py" --password user "$W/fx/field-enc.pdf" "$W/signed/field-enc.pdf" approvals.director "${ROOTS[@]}" || fail=1
python3 -W ignore "$ROOT/tests/verify_check.py" --password=user "$BIN" "$W/signed/field-enc.pdf" valid "${ROOTS[@]}" || fail=1
"$BIN" sign "$W/fx/field-lock.pdf" --field Approver --certify forms --image "$W/fx/sig.png" --out "$W/signed/field-cert.pdf" >/dev/null
check --certify=2 "$W/fx/field-lock.pdf" "$W/signed/field-cert.pdf"
python3 -W ignore "$ROOT/tests/check_field.py" --certify 2 --lock company "$W/fx/field-lock.pdf" "$W/signed/field-cert.pdf" Approver "${ROOTS[@]}" || fail=1
vcheck "$W/signed/field-cert.pdf" valid
"$BIN" sign "$W/fx/field-enc.pdf" --password user --field approvals.director --certify forms --timestamp "$TSA" --ltv \
  --out "$W/signed/field-enc-cert.pdf" >/dev/null
check --certify=2 --timestamp --ltv --password=user "$W/fx/field-enc.pdf" "$W/signed/field-enc-cert.pdf"
python3 -W ignore "$ROOT/tests/check_field.py" --certify 2 --password user "$W/fx/field-enc.pdf" "$W/signed/field-enc-cert.pdf" approvals.director "${ROOTS[@]}" || fail=1
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
# A key that wants the PIN again for every signature (CKA_ALWAYS_AUTHENTICATE).
AA=(env SOFTHSM2_CONF="$ALWAYS_AUTH_CONF")
"${AA[@]}" "$BIN" sign "$W/fx/presigned.pdf" --out "$W/signed/always-auth.pdf" >/dev/null || fail=1
check "$W/fx/presigned.pdf" "$W/signed/always-auth.pdf"
mkdir -p "$W/batch-aa"
for f in plain objstm form; do cp "$W/fx/$f.pdf" "$W/batch-aa/"; done
"${AA[@]}" "$BIN" sign "$W/batch-aa/plain.pdf" "$W/batch-aa/objstm.pdf" "$W/batch-aa/form.pdf" \
  --timestamp "$TSA" >"$W/batch-aa.out" || fail=1
[ "$(grep -c '^Signed:' "$W/batch-aa.out")" = 3 ] && echo "PASS batch with a per-signature PIN" \
  || { echo "FAIL batch with a per-signature PIN: $(cat "$W/batch-aa.out")"; fail=1; }
for f in plain objstm form; do check --timestamp "$W/fx/$f.pdf" "$W/batch-aa/${f}_signed.pdf"; done
mkdir -p "$W/batch-aa-bad"
for f in plain objstm; do cp "$W/fx/$f.pdf" "$W/batch-aa-bad/"; done
if TRACKMYSIGN_PIN=00000000 "${AA[@]}" "$BIN" sign "$W/batch-aa-bad/plain.pdf" "$W/batch-aa-bad/objstm.pdf" 2>"$W/err"; then
  echo "FAIL wrong PIN accepted for the per-signature key"; fail=1
elif [ "$(grep -c "Wrong PIN" "$W/err")" = 1 ] && ! ls "$W/batch-aa-bad"/*_signed.pdf >/dev/null 2>&1; then
  echo "PASS wrong PIN rejected for the per-signature key"
else
  echo "FAIL: $(cat "$W/err")"; fail=1
fi
# A driver that fails to load must not hide the token behind another one.
: > "$W/broken-pkcs11.so"
if TRACKMYSIGN_PKCS11_MODULE="$W/broken-pkcs11.so:$TRACKMYSIGN_PKCS11_MODULE" "$BIN" certs >"$W/certs" 2>&1 \
  && grep -q "not loaded" "$W/certs" && grep -q "RAHUL TEST DIRECTOR" "$W/certs"; then
  echo "PASS broken driver skipped"
else
  echo "FAIL broken driver: $(cat "$W/certs")"; fail=1
fi
# Days left on each certificate; an expired one is refused unless --allow-expired.
"$BIN" certs >"$W/certs" 2>&1 || fail=1
if grep -Eq "Valid until: .* \(expires in 7(29|30) days\)" "$W/certs" \
   && grep -Eq "Valid until: 01 Jan 2025 \(EXPIRED [0-9]+ days ago\)" "$W/certs" \
   && grep -q "OLD TEST DIRECTOR (Personal)" "$W/certs"; then
  echo "PASS certs shows days left"
else
  echo "FAIL certs expiry: $(cat "$W/certs")"; fail=1
fi
old=$(grep -o '^[0-9]*\. OLD TEST DIRECTOR' "$W/certs" | cut -d. -f1)
if "$BIN" sign "$W/fx/plain.pdf" --cert "$old" --out "$W/expired.pdf" >/dev/null 2>"$W/err"; then
  echo "FAIL signed with an expired certificate"; fail=1
elif grep -q "expired .* --allow-expired" "$W/err" && [ ! -e "$W/expired.pdf" ]; then
  echo "PASS expired certificate refused"
else
  echo "FAIL: $(cat "$W/err")"; fail=1
fi
if "$BIN" sign "$W/fx/plain.pdf" --cert "$old" --allow-expired --out "$W/expired.pdf" >/dev/null 2>"$W/err" \
   && grep -q "Warning: .* has expired" "$W/err" && [ -s "$W/expired.pdf" ]; then
  echo "PASS --allow-expired signs with a warning"
else
  echo "FAIL --allow-expired: $(cat "$W/err")"; fail=1
fi
# Certificate details and export: the public certificate as on the token,
# fingerprint and serial as openssl reads them, the chain up to the root.
C=$W/certexport
mkdir -p "$C"
"$BIN" certs --details >"$C/details" 2>&1 || fail=1
"$BIN" certs --export 1 --out "$C/me.cer" >/dev/null || fail=1
"$BIN" certs --export 1 --out "$C/me.pem" --pem >/dev/null || fail=1
"$BIN" certs --export 1 --out "$C/me.p7b" --chain >/dev/null || fail=1
(cd "$C" && "$BIN" certs --export 1 >/dev/null) || fail=1
fp=$(openssl x509 -inform DER -in "$C/me.cer" -noout -fingerprint -sha256 | cut -d= -f2)
serial=$(openssl x509 -inform DER -in "$C/me.cer" -noout -serial | cut -d= -f2)
if cmp -s "$C/me.cer" "$TEST_PKI/sign.der" \
   && openssl x509 -in "$C/me.pem" -outform DER | cmp -s - "$TEST_PKI/sign.der" \
   && [ "$(openssl pkcs7 -inform DER -in "$C/me.p7b" -print_certs | grep -c '^subject=')" = 3 ] \
   && openssl pkcs7 -inform DER -in "$C/me.p7b" -print_certs | grep -q "CN = Test CCA India Root" \
   && cmp -s "$C/RAHUL_TEST_DIRECTOR_DSC.cer" "$TEST_PKI/sign.der" \
   && grep -q "SHA-256: $fp" "$C/details" && grep -q "Serial number: $serial" "$C/details" \
   && grep -q "Key: RSA 2048" "$C/details" \
   && grep -q "Chain: RAHUL TEST DIRECTOR <- Test Sub-CA for Class 3 Individual 2026 <- Test CCA India Root" "$C/details"; then
  echo "PASS certificate details and export"
else
  echo "FAIL certificate export: $(cat "$C/details")"; fail=1
fi

# Verification reports (PDF and JSON) for auditors: signed file, then the texts the report must show.
mkdir -p "$W/reports"
report() { python3 -W ignore "$ROOT/tests/check_report.py" "$@" || fail=1; }
"$BIN" sign "$W/fx/plain.pdf" --reason "स्वीकृत" --location "चेन्नई" --out "$W/signed/indic.pdf" >/dev/null
report "$BIN" "$W/signed/twice.pdf" "$W/reports" "3 signatures — all valid, document unchanged since the last signature" \
  "Signer CA AUDITOR PARTNER" "Coverage 2 later revisions: signatures only" "Coverage Covers the whole document" \
  "Organisation Personal" "Issuer Test Sub-CA for Class 3 Individual 2026" "Timestamp None"
report "$BIN" "$W/tampered-twice.pdf" "$W/reports" "3 signatures — all INVALID" "Signature 1 of 3: Invalid" \
  "Notes The document digest does not match: the signed bytes were changed."
report "$BIN" "$W/changed.pdf" "$W/reports" "CONTENT CHANGED after signature 1" "later revisions: CONTENT CHANGED"
report "$BIN" "$W/signed/cert-forms-approved.pdf" "$W/reports" "2 signatures — all valid" \
  "Certification Level 2: form filling and signing allowed"
report "$BIN" "$W/signed/ltv.pdf" "$W/reports" "Timestamp Present (the timestamp token is not verified)"
report --password=own "$BIN" "$W/signed/enc-aes256.pdf" "$W/reports" "1 signature — valid, document unchanged since it was signed" \
  "Protection Password-protected"
report "$BIN" "$W/signed/indic.pdf" "$W/reports" "Reason Svikrita (transliterated)" "Location Chennai (transliterated)"
report "$BIN" "$W/fx/plain.pdf" "$W/reports" "No signatures found."
# Verifying a folder: valid, multi-signature, tampered, changed, unsigned, encrypted and
# damaged PDFs; a hidden folder and a non-PDF are skipped. Then a folder with no problems.
F=$W/folder
mkdir -p "$F/sub" "$F/.hidden"
cp "$W/signed/plain.pdf" "$F/valid.pdf"
cp "$W/signed/twice.pdf" "$F/sub/three-signatures.pdf"
cp "$W/tampered-plain.pdf" "$F/tampered.pdf"
cp "$W/changed.pdf" "$F/sub/changed.pdf"
cp "$W/fx/plain.pdf" "$F/unsigned.PDF"
cp "$W/signed/enc-aes256.pdf" "$F/encrypted.pdf"
cp "$W/fx/plain.pdf" "$F/.hidden/skipped.pdf"
printf '%%PDF-1.7\n1 0 obj << /Type /Catalog' > "$F/damaged.pdf"
printf 'not a pdf' > "$F/notes.txt"
folder() { python3 -W ignore "$ROOT/tests/check_folder.py" "$@" || fail=1; }
folder --recursive "$BIN" "$F" "$W/reports" 2 valid.pdf=all_valid sub/three-signatures.pdf=all_valid \
  tampered.pdf=some_invalid sub/changed.pdf=content_changed unsigned.PDF=unsigned encrypted.pdf=needs_password \
  damaged.pdf=unreadable
folder --password=user "$BIN" "$F" "$W/reports" 2 valid.pdf=all_valid tampered.pdf=some_invalid \
  unsigned.PDF=unsigned encrypted.pdf=all_valid damaged.pdf=unreadable
mkdir -p "$W/folder-ok"
cp "$W/signed/plain.pdf" "$W/signed/twice.pdf" "$W/fx/form.pdf" "$W/folder-ok/"
folder "$BIN" "$W/folder-ok" "$W/reports" 0 plain.pdf=all_valid twice.pdf=all_valid form.pdf=unsigned
folder --require-signed "$BIN" "$W/folder-ok" "$W/reports" 2 plain.pdf=all_valid twice.pdf=all_valid form.pdf=unsigned
if "$BIN" verify-folder "$F" --recursive >"$W/folder.out" 2>&1; then
  echo "FAIL verify-folder reported success"; fail=1
elif grep -q "^INVALID SIGNATURE  *tampered.pdf" "$W/folder.out" \
   && grep -q "^NEEDS A PASSWORD  *encrypted.pdf .*(--password)" "$W/folder.out" \
   && grep -q "^ALL VALID  *sub/three-signatures.pdf  (3 signatures: " "$W/folder.out" \
   && grep -qx "7 files: 2 all valid, 2 with problems, 1 unsigned, 1 unreadable, 1 needs a password" "$W/folder.out"; then
  echo "PASS verify-folder text output"
else
  echo "FAIL verify-folder text: $(cat "$W/folder.out")"; fail=1
fi
if "$BIN" verify-folder "$W/no-such-folder" 2>"$W/err"; then
  echo "FAIL verify-folder of a missing folder succeeded"; fail=1
else
  grep -q "reading .*no-such-folder" "$W/err" && echo "PASS missing folder reported" || { echo "FAIL: $(cat "$W/err")"; fail=1; }
fi
# GST portal signing: the listener with a throwaway CA, approving every request
# (crates/portal-bridge/examples/portal-test-server.rs, never part of the app),
# a client acting like the portal page, and the portal's own JavaScript run on
# the frames it got.
PORTAL_BIN=${PORTAL_TEST_SERVER:-${CARGO_TARGET_DIR:-$ROOT/target}/debug/examples/portal-test-server}
[ -n "${PORTAL_TEST_SERVER:-}" ] || cargo build -q --manifest-path "$ROOT/Cargo.toml" -p portal-bridge --example portal-test-server
P=$W/portal
mkdir -p "$P"
PP=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
"$PORTAL_BIN" "$P" "$PP" >"$P/server.out" 2>"$P/server.err" &
PORTAL_PID=$!
trap 'kill $SVC_PID $PORTAL_PID 2>/dev/null' EXIT
for _ in $(seq 100); do grep -q "^PORT $PP" "$P/server.out" && break; sleep 0.1; done
openssl x509 -in "$TEST_PKI/sign.pem" -outform DER -out "$P/expected-signer.der"
portal_sign() {  # tobesigned, PAN, name
  local d=$P/$3
  mkdir -p "$d"
  if ! python3 "$ROOT/tests/portal_client.py" sign "$P/ca.cer" "$PP" https://services.gst.gov.in "$d" "$1" "$2"; then
    echo "FAIL portal $3: no reply ($(cat "$P/server.err"))"; fail=1; return
  fi
  node "$ROOT/tests/portal_compat.js" "$d/greeting.txt" "$d/reply.txt" 2.8 "$d/sig.txt" || { fail=1; return; }
  python3 -c 'import base64, sys; t = open(sys.argv[1]).read(); sys.stdout.buffer.write(base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))' \
    "$d/sig.txt" >"$d/sig.der"
  openssl asn1parse -inform DER -in "$d/sig.der" >"$d/asn1.txt"
  if openssl cms -verify -inform DER -in "$d/sig.der" -noverify -out "$d/content" -signer "$d/signer.pem" 2>"$d/verify.err" \
     && [ "$(cat "$d/content")" = "$1" ] \
     && openssl x509 -in "$d/signer.pem" -outform DER | cmp -s - "$P/expected-signer.der" \
     && [ "$(grep -c ':contentType$' "$d/asn1.txt")" = 1 ] && [ "$(grep -c ':signingTime$' "$d/asn1.txt")" = 1 ] \
     && [ "$(grep -c ':messageDigest$' "$d/asn1.txt")" = 1 ] && [ "$(grep -c 'OBJECT *:sha1$' "$d/asn1.txt")" = 2 ] \
     && ! grep -qi 'signingCertificate\|cont \[ 1 \]' "$d/asn1.txt" \
     && head -c 11 "$d/reply.txt" | grep -qx 'signature= ' && grep -q '^CommonName= RAHUL TEST DIRECTOR$' "$d/reply.txt"; then
    echo "PASS portal signature over $3 verifies (attached content, SHA-1, three signed attributes)"
  else
    echo "FAIL portal $3: $(cat "$d/verify.err" "$d/reply.txt")"; fail=1
  fi
}
portal_sign ABCDE1234F ABCDE1234F registration
portal_sign "$(printf 'return' | sha256sum | cut -d' ' -f1)" ABCDE1234F return
for origin in https://evil.example http://services.gst.gov.in https://gst.gov.in.evil.example; do
  if python3 "$ROOT/tests/portal_client.py" refused "$P/ca.cer" "$PP" "$origin"; then
    echo "PASS portal refuses $origin"
  else
    echo "FAIL portal accepted $origin"; fail=1
  fi
done
grep -q 'refused a page from "https://evil.example"' "$P/server.err" || { echo "FAIL refusal not logged"; fail=1; }
for ip in $(hostname -I 2>/dev/null); do
  if python3 -c 'import socket, sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)' "$ip" "$PP" 2>/dev/null; then
    echo "FAIL portal listener answers on $ip"; fail=1
  else
    echo "PASS portal listener not reachable on $ip"
  fi
done
kill $PORTAL_PID 2>/dev/null

[ $fail = 0 ] && echo "ALL PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
