#!/usr/bin/env bash
# Live check of public timestamp servers (needs internet; not part of tests/run.sh).
#
# Usage: tests/manual/tsa_check.sh [URL...]
#   Without URLs: the servers suggested in Settings plus the Indian candidates below.
#
# For each server:
#   1. a raw RFC 3161 request (openssl ts): HTTP status, time, TSA certificate
#      subject and issuer, and whether the token verifies to a public root and
#      to the CCA India 2022 root;
#   2. sign a fixture on the SoftHSM test token with `--timestamp <url>` and
#      validate it with pyHanko (timestamp intact, valid and trusted);
#   3. the same with `--ltv`, validated from the DSS alone (only meaningful
#      when the TSA chain's OCSP/CRL servers are reachable).
# A TSA whose root is in no public bundle (FreeTSA) needs EXTRA_ROOTS: PEM
# files, separated by spaces, that count as trusted roots. So does a chain
# that the TSA sends with a cross-certificate to an older root (DigiCert,
# via DigiCert Assured ID Root CA): pyHanko then mixes up the two G4 roots
# when checking the OCSP answers in the DSS, and --ltv fails unless the
# older root is trusted too.
# Needs what tests/run.sh needs. Prints one table row per server; exit code 1
# if any server failed.
set -uo pipefail
shopt -s nullglob
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=${WORK:-$(mktemp -d)}
BIN=${TRACKMYSIGN_BIN:-$ROOT/target/debug/trackmysign}
BUNDLE=${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}
export XDG_DATA_HOME=$W/data

# Timestamp hosts of Indian licensed CAs (CCA). None publishes a free public
# address (eMudhra sells its TSA as a subscription) and none answered a
# request from outside India, so they stay out of the suggestions until one
# grants a token without an account.
INDIAN=(
  http://timestamping.e-mudhra.com
  http://timestamping.ncode.in
  http://timestamp.vsign.in
  http://timestamp.safescrypt.com
  http://tsa.certificate.digital
  http://tsa.pantasign.com
)
SUGGESTED=(
  http://timestamp.digicert.com
  http://timestamp.sectigo.com
  http://ts.ssl.com
  http://timestamp.globalsign.com/tsa/r6advanced1
  http://time.certum.pl
  https://freetsa.org/tsr
)
if [ $# -gt 0 ]; then URLS=("$@"); else URLS=("${INDIAN[@]}" "${SUGGESTED[@]}"); fi

# Test token and local OCSP/CRL server for the signer's own chain.
PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
export TEST_SERVICES_URL=http://127.0.0.1:$PORT
eval "$("$ROOT/tests/make-test-token.sh" "$W/token")"
python3 "$ROOT/tests/services.py" "$TEST_PKI" "$PORT" &
SVC_PID=$!
trap 'kill $SVC_PID 2>/dev/null' EXIT
for _ in $(seq 50); do curl -sf "$TEST_SERVICES_URL/root.der" -o /dev/null && break; sleep 0.1; done
python3 "$ROOT/tests/make_fixtures.py" "$W/fx" >/dev/null
openssl x509 -inform der -in "$ROOT/crates/trackmysign-core/src/roots/cca-india-2022.der" -out "$W/cca.pem"
cat "$BUNDLE" "$W/cca.pem" ${EXTRA_ROOTS:-} > "$W/anchors.pem"
printf hello > "$W/data.txt"

# Roots (from the bundle or the CCA root) named in a token's chain: <certs.pem> <out-prefix>.
find_root() {
  python3 -W ignore - "$1" "$W/anchors.pem" "$2" <<'PY'
import sys
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
certs = x509.load_pem_x509_certificates(open(sys.argv[1], "rb").read())
anchors = x509.load_pem_x509_certificates(open(sys.argv[2], "rb").read())
# Any anchor named in the chain (a token may carry a cross-certificate
# whose issuer is no longer in the bundle, so collect all of them).
names = {c.subject for c in certs} | {c.issuer for c in certs}
found = [a for a in anchors if a.subject in names]
for n, a in enumerate(found):
    open(f"{sys.argv[3]}{n}.pem", "wb").write(a.public_bytes(Encoding.PEM))
print("; ".join(dict.fromkeys(a.subject.rfc4514_string() for a in found)))
PY
}

# First line of what went wrong: the CLI's error, else pyHanko's problems.
why() { cat "$@" 2>/dev/null | grep -E '^(Error|   - )' | head -1 | sed 's/^ *- //'; }

printf '%s\n' "TSA | raw request | TSA certificate | chain | sign + pyHanko | --ltv"
fail=0
i=0
for url in "${URLS[@]}"; do
  i=$((i + 1))
  d=$W/tsa$i
  mkdir -p "$d"
  openssl ts -query -data "$W/data.txt" -sha256 -cert -out "$d/req.tsq" 2>/dev/null
  raw=$(curl -sS -m 30 -H 'Content-Type: application/timestamp-query' --data-binary @"$d/req.tsq" \
    -o "$d/resp.tsr" -w '%{http_code} %{time_total}s' "$url" 2>&1 | tail -1)
  status=$(openssl ts -reply -in "$d/resp.tsr" -text 2>/dev/null | sed -n 's/^Status: //p')
  if [ "$status" != "Granted." ]; then
    echo "$url | FAIL ($raw, ${status:-no timestamp response}) | - | - | - | -"
    fail=1
    continue
  fi
  raw="granted, ${raw#* }"
  openssl ts -reply -in "$d/resp.tsr" -token_out -out "$d/token.der" 2>/dev/null
  openssl pkcs7 -inform der -in "$d/token.der" -print_certs -out "$d/certs.pem" 2>/dev/null
  # The signing certificate is the first one that is not a CA.
  signer=$(python3 -W ignore - "$d/certs.pem" <<'PY'
import sys
from cryptography import x509
for c in x509.load_pem_x509_certificates(open(sys.argv[1], "rb").read()):
    try:
        if c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            continue
    except x509.ExtensionNotFound:
        pass
    print(f"{c.subject.rfc4514_string()} (issuer: {c.issuer.rfc4514_string()})")
    break
PY
  )
  anchor=$(find_root "$d/certs.pem" "$d/root" 2>/dev/null)
  chain="no known root"
  if openssl ts -verify -in "$d/resp.tsr" -queryfile "$d/req.tsq" -CAfile "$W/cca.pem" \
       -untrusted "$d/certs.pem" >/dev/null 2>&1; then
    chain="CCA India"
  elif openssl ts -verify -in "$d/resp.tsr" -queryfile "$d/req.tsq" -CAfile "$W/anchors.pem" \
       -untrusted "$d/certs.pem" >/dev/null 2>&1; then
    chain="root: ${anchor:-?}"
  fi
  roots=("$TEST_PKI/root.pem" "$d"/root*.pem)
  start=$(date +%s.%N)
  if "$BIN" sign "$W/fx/plain.pdf" --timestamp "$url" --out "$d/ts.pdf" >/dev/null 2>"$d/sign.err" \
     && python3 -W ignore "$ROOT/tests/validate.py" --timestamp "$W/fx/plain.pdf" "$d/ts.pdf" "${roots[@]}" >"$d/ts.log"; then
    signed="PASS ($(printf '%.1f' "$(echo "$(date +%s.%N) - $start" | bc)")s)"
  else
    signed="FAIL: $(why "$d/sign.err" "$d/ts.log")"
    fail=1
  fi
  if "$BIN" sign "$W/fx/plain.pdf" --timestamp "$url" --ltv --out "$d/ltv.pdf" >/dev/null 2>"$d/ltv.err" \
     && python3 -W ignore "$ROOT/tests/validate.py" --timestamp --ltv "$W/fx/plain.pdf" "$d/ltv.pdf" "${roots[@]}" >"$d/ltv.log"; then
    ltv=PASS
  else
    ltv="FAIL: $(why "$d/ltv.err" "$d/ltv.log")"
    fail=1
  fi
  echo "$url | $raw | $signer | $chain | $signed | $ltv"
done
echo "Details in $W"
exit $fail
