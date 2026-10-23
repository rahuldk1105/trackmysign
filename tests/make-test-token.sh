#!/usr/bin/env bash
# Creates a SoftHSM token that looks like an Indian Class 3 DSC:
# root CA -> sub CA -> signing cert (+ a separate encryption cert), keys on the token.
# Also a timestamp authority (root -> TSA CA -> TSA) and an OCSP responder, with
# CRL/OCSP/issuer addresses under $TEST_SERVICES_URL (served by tests/services.py).
# Usage: tests/make-test-token.sh <workdir>   (prints env exports)
set -euo pipefail
W=${1:?workdir}
SVC=${TEST_SERVICES_URL:-http://127.0.0.1:18339}
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
cat >> ext.cnf <<X
[sd_subca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:$SVC/root.crl
authorityInfoAccess=caIssuers;URI:$SVC/root.der
[sd_sign_ltv]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
authorityKeyIdentifier=keyid
authorityInfoAccess=OCSP;URI:$SVC/ocsp,caIssuers;URI:$SVC/sub.der
crlDistributionPoints=URI:$SVC/sub.crl
[sd_tsa]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=critical,timeStamping
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:$SVC/tsaca.crl
authorityInfoAccess=caIssuers;URI:$SVC/tsaca.der
[sd_ocsp]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=OCSPSigning
noCheck=ignored
authorityKeyIdentifier=keyid
X
q() { "$@" >/dev/null 2>&1; }
q openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 -subj "/C=IN/O=Test CCA/CN=Test CCA India Root" -extensions sd_ca -config <(cat /etc/ssl/openssl.cnf ext.cnf)
q openssl req -newkey rsa:2048 -nodes -keyout sub.key -out sub.csr -subj "/C=IN/O=Test DSC Provider/CN=Test Sub-CA for Class 3 Individual 2026"
q openssl x509 -req -in sub.csr -CA root.pem -CAkey root.key -CAcreateserial -out sub.pem -days 3650 -extfile ext.cnf -extensions sd_subca
for kind in sign enc; do
  ext=sd_$kind; [ $kind = sign ] && ext=sd_sign_ltv
  q openssl req -newkey rsa:2048 -nodes -keyout $kind.key -out $kind.csr -subj "/C=IN/O=Personal/CN=RAHUL TEST DIRECTOR"
  q openssl x509 -req -in $kind.csr -CA sub.pem -CAkey sub.key -CAcreateserial -out $kind.pem -days 730 -extfile ext.cnf -extensions $ext
  openssl pkcs8 -topk8 -nocrypt -in $kind.key -outform DER -out $kind.key.der
  openssl x509 -in $kind.pem -outform DER -out $kind.der
done
openssl x509 -in root.pem -outform DER -out root.der
openssl x509 -in sub.pem -outform DER -out sub.der

# Timestamp authority under its own CA (not on the token, so its issuer must be fetched).
q openssl req -newkey rsa:2048 -nodes -keyout tsaca.key -out tsaca.csr -subj "/C=IN/O=Test CCA/CN=Test TSA CA"
q openssl x509 -req -in tsaca.csr -CA root.pem -CAkey root.key -CAcreateserial -out tsaca.pem -days 3650 -extfile ext.cnf -extensions sd_subca
q openssl req -newkey rsa:2048 -nodes -keyout tsa.key -out tsa.csr -subj "/C=IN/O=Test CCA/CN=Test Timestamp Authority"
q openssl x509 -req -in tsa.csr -CA tsaca.pem -CAkey tsaca.key -CAcreateserial -out tsa.pem -days 3650 -extfile ext.cnf -extensions sd_tsa
q openssl req -newkey rsa:2048 -nodes -keyout ocsp.key -out ocsp.csr -subj "/C=IN/O=Test DSC Provider/CN=Test OCSP Responder"
q openssl x509 -req -in ocsp.csr -CA sub.pem -CAkey sub.key -CAcreateserial -out ocsp.pem -days 3650 -extfile ext.cnf -extensions sd_ocsp

# OCSP database of the sub CA, and an empty CRL from each CA.
: > sub-index.txt
echo "unique_subject = no" > sub-index.txt.attr
for c in sign enc ocsp; do
  exp=$(date -u -d "$(openssl x509 -in $c.pem -noout -enddate | cut -d= -f2)" +%y%m%d%H%M%SZ)
  ser=$(openssl x509 -in $c.pem -noout -serial | cut -d= -f2)
  dn=$(openssl x509 -in $c.pem -noout -subject -nameopt compat | sed 's/^subject=//')
  printf 'V\t%s\t\t%s\tunknown\t%s\n' "$exp" "$ser" "$dn" >> sub-index.txt
done
mkdir -p www
for ca in root sub tsaca; do
  mkdir -p ca-$ca && : > ca-$ca/index.txt && echo 01 > ca-$ca/crlnumber
  printf '[ca]\ndefault_ca=c\n[c]\ndatabase=%s\ncrlnumber=%s\ndefault_md=sha256\ndefault_crl_days=30\n' \
    "$PWD/ca-$ca/index.txt" "$PWD/ca-$ca/crlnumber" > ca-$ca/ca.cnf
  q openssl ca -gencrl -config ca-$ca/ca.cnf -keyfile $ca.key -cert $ca.pem -out ca-$ca/crl.pem
  openssl crl -in ca-$ca/crl.pem -outform DER -out www/$ca.crl
  openssl x509 -in $ca.pem -outform DER -out www/$ca.der
done

q softhsm2-util --init-token --free --label "HYP2003 TEST" --so-pin 87654321 --pin 12345678
P="pkcs11-tool --module $MOD --login --pin 12345678"
q $P --write-object sign.key.der --type privkey --id 01 --label "sign"
q $P --write-object sign.der --type cert --id 01 --label "sign"
q $P --write-object enc.key.der --type privkey --id 02 --label "enc"
q $P --write-object enc.der --type cert --id 02 --label "enc"
q $P --write-object sub.der --type cert --id 10 --label "subca"
q $P --write-object root.der --type cert --id 11 --label "root"

echo "export SOFTHSM2_CONF=$SOFTHSM2_CONF TRACKMYSIGN_PKCS11_MODULE=$MOD TRACKMYSIGN_PIN=12345678 TEST_PKI=$W/pki"
