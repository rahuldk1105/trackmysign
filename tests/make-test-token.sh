#!/usr/bin/env bash
# Creates a SoftHSM token that looks like an Indian Class 3 DSC:
# root CA -> sub CA -> signing cert (+ a separate encryption cert), keys on the token.
# Usage: tests/make-test-token.sh <workdir>   (prints env exports)
set -euo pipefail
W=${1:?workdir}
mkdir -p "$W/pki" "$W/softhsm"
cd "$W/pki"
MOD=$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -1)
export SOFTHSM2_CONF="$W/softhsm2.conf"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$W/softhsm" > "$SOFTHSM2_CONF"
rm -rf "$W/softhsm"/*

cat > ext.cnf <<'X'
[sd_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[sd_sign]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
authorityKeyIdentifier=keyid
[sd_enc]
basicConstraints=CA:FALSE
keyUsage=critical,keyEncipherment,dataEncipherment
X
q() { "$@" >/dev/null 2>&1; }
q openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 -subj "/C=IN/O=Test CCA/CN=Test CCA India Root" -extensions sd_ca -config <(cat /etc/ssl/openssl.cnf ext.cnf)
q openssl req -newkey rsa:2048 -nodes -keyout sub.key -out sub.csr -subj "/C=IN/O=Test DSC Provider/CN=Test Sub-CA for Class 3 Individual 2026"
q openssl x509 -req -in sub.csr -CA root.pem -CAkey root.key -CAcreateserial -out sub.pem -days 3650 -extfile ext.cnf -extensions sd_ca
for kind in sign enc; do
  q openssl req -newkey rsa:2048 -nodes -keyout $kind.key -out $kind.csr -subj "/C=IN/O=Personal/CN=RAHUL TEST DIRECTOR"
  q openssl x509 -req -in $kind.csr -CA sub.pem -CAkey sub.key -CAcreateserial -out $kind.pem -days 730 -extfile ext.cnf -extensions sd_$kind
  openssl pkcs8 -topk8 -nocrypt -in $kind.key -outform DER -out $kind.key.der
  openssl x509 -in $kind.pem -outform DER -out $kind.der
done
openssl x509 -in root.pem -outform DER -out root.der
openssl x509 -in sub.pem -outform DER -out sub.der

q softhsm2-util --init-token --free --label "HYP2003 TEST" --so-pin 87654321 --pin 12345678
P="pkcs11-tool --module $MOD --login --pin 12345678"
q $P --write-object sign.key.der --type privkey --id 01 --label "sign"
q $P --write-object sign.der --type cert --id 01 --label "sign"
q $P --write-object enc.key.der --type privkey --id 02 --label "enc"
q $P --write-object enc.der --type cert --id 02 --label "enc"
q $P --write-object sub.der --type cert --id 10 --label "subca"
q $P --write-object root.der --type cert --id 11 --label "root"

echo "export SOFTHSM2_CONF=$SOFTHSM2_CONF TRACKMYSIGN_PKCS11_MODULE=$MOD TRACKMYSIGN_PIN=12345678 TEST_PKI=$W/pki"
