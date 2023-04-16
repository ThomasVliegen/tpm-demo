#!/bin/bash

rm -f ./certs/index.*
touch ./certs/index.txt
if [ ! -f ./certs/serial ]; then
	echo 1234 > ./certs/serial
fi

if [ "$1" == "clean" ]; then
	rm -f ./certs/*.pem
	rm -f ./certs/*.der
	rm -f ./certs/*.old

	# cleanup the ./examples/csr/csr generated
	rm -f ./certs/tpm-*.csr

	exit 0
fi

if [ ! -f ./certs/ca-ecc-key.pem ]; then
    openssl ecparam -out ./certs/ca-ecc-key.par -name prime256v1
    openssl req -config ./certs/ecc-ca.cnf -extensions v3_ca -x509 -nodes -newkey ec:./certs/ca-ecc-key.par -keyout ./certs/ca-ecc-key.pem -out ./certs/ca-ecc-cert.pem -sha256 -days 3650 -batch -subj "/C=NL/ST=Noord-Brabant/L='s-Hertogenbosch/O=DemoOrg/OU=TPM Demo/CN=TPM Demo CA"
    rm ./certs/ca-ecc-key.par

    openssl x509 -in ./certs/ca-ecc-cert.pem -inform PEM -out ./certs/ca-ecc-cert.der -outform DER
    openssl ec -in ./certs/ca-ecc-key.pem -inform PEM -out ./certs/ca-ecc-key.der -outform DER
fi

if [ -f ./certs/tpm-ecc-cert.csr ]; then
    openssl ca -config ./certs/ecc-ca.cnf -extensions server_cert -days 365 -notext -md sha256 -in ./certs/tpm-ecc-cert.csr -out ./certs/server-ecc-cert.pem -batch
    openssl x509 -in ./certs/server-ecc-cert.pem -outform der -out ./certs/server-ecc-cert.der
else
    echo "No TPM ECC key CSR found! Make sure to run ./build/csr first."
fi
