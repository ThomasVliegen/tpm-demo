# tpm-demo

This repo contains the code used in the practical assignment of the HW/SW security workshop.

## Building

The code should build pretty much everywhere, but has only been tested specifically for the workshop with the supplied makefiles on Raspberry Pi using the instructions below.

### Platform

Tested on Raspberry Pi 3 with Raspberry OS Lite (32-bit).

Make sure the TPM is correctly installed and the device shows up as `/dev/tpm0`. For example, run `sudo tpm2_getrandom 10 --hex` to verify communication with the TPM works.

### Dependencies

Start by installing some additional packages:

```sh
sudo apt-get install vim git libtool automake tpm2-tools
```

Build and install WolfSSL:

```sh
git clone --branch=v5.6.0-stable https://github.com/wolfSSL/wolfssl.git
cd wolfssl
sudo ./autogen.sh
sudo ./configure --enable-certgen --enable-certreq --enable-certext --enable-pkcs7 --enable-cryptocb --enable-aescfb
sudo make
sudo make install
sudo ldconfig
```

Build and install WolfTPM:

```sh
git clone --branch=v3.0.0 https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
sudo ./autogen.sh
sudo ./configure --enable-devtpm # (optional: --enable-debug)
sudo make
sudo make install
sudo ldconfig
```

Build the tools in this repository:

```sh
git clone https://github.com/ThomasVliegen/tpm-demo.git
cd tpm-demo
sudo make
```

## Part 1: Running an insecure HTTP server

From your demo-tpm checkout, run the HTTP server without any security using:
```sh
./build/plain_http_server
```

This opens a webserver listening on port `11111`. Now perform a request to this server using Postman or your browser.

_Exercise: Can you intercept and read the response in plain text on the network using Wireshark?_

## Part 2: Setting up the TPM and certificates

First of all, we need to generate a keypair on the TPM. Since only the TPM has access to the private key, we need to ask it to create a Certificate Signing Request (CSR) for us that we can send to a CA.

The `csr` tool creates a persistent key for you on index `0x81008123` if there does not exist any yet.

```sh
sudo ./build/csr
```

This tool creates a CSR (`tpm-ecc-cert.csr`) and puts it in the `certs/` directory.

Then, we need a CA that can sign the TPM CSR. The `generate_certificates.sh` script first creates a new CA key pair and subsequently signs our TPM CSR with that CA:

```sh
./certs/generate_certificates.sh
```

We will use `ca-ecc-cert.pem` as the CA certificate and `server-ecc-cert.pem` as the certificate used by our TLS server.

## Part 3: Running a secure TLS server

Now we can run a TLS server that uses `server-ecc-cert.pem` to set up a TLS session.

```sh
sudo ./build/tls_server
```

This opens a webserver running on port `11111`. Now perform a request to this server using Postman or your browser. If everything is set up correctly, these clients will complain that this connection is not trusted. For the purposes of this demo, you can ignore this warning and let them

_Exercise: Why do these tools warn you about this connection?_

_Exercise: Using Wireshark, find the point in the TLS handshake where this certificate is exchanged. Can you find the public key information in this certificate. Compare this public key to the one we created in the TPM. (Hint: `tpm2-tools` has some useful tools to interact with the TPM) (Hint 2: We created the key on index `0x81008123`)_

_Exercise: Can you make your client (Postman or browser) trust this connection and not display a security warning?_

## License

This repository makes use of the examples provided by [WolfSSL/WolfTPM](https://github.com/wolfSSL) distributed under the GPLv2 license.

This repository makes use of [tiny-web-server](https://github.com/shenfeng/tiny-web-server) distributed under the MIT license.
