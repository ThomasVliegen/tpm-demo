# tpm-demo

This repo contains the code used in the practical assignment of the HW/SW security workshop.

## Compatibility

The code should build pretty much everywhere, however it's only been tested specifically for the workshop with the supplied makefiles on Raspberry Pi 3 Model B+ with Raspberry OS Lite (32-bit).

The [LetsTrust-TPM](https://letstrust.de) is used as Trusted Platform Module to safely store cryptographic keys.

Some packages are used in this demo, these can be installed by running:
```sh
sudo apt-get install vim git libtool automake tpm2-tools
```

### Installing TPM

First, make sure the TPM is connected to your Raspberry Pi.

The LetsTrust TPM module is supported directly by Linux, starting with Kernel 4.14.85
The TPM can be activated as `/dev/tpm0` as follows:

Edit the Raspberry Pi configuration by running:
```sh
sudo nano /boot/firmware/config.txt
```

Add these two lines:
```sh
dtparam=spi=on
dtoverlay=tpm-slb9670 
```

Finally reboot the Pi by running:
```sh
sudo reboot
```

Make sure the TPM is correctly installed and the device shows up as `/dev/tpm0`. You can verify communication with the TPM by running `sudo tpm2_getrandom 10 --hex`.

## Structure 

This assignment consists out of 3 parts. You will start by running an insecure HTTP server in part 1. Next, you will generate a certificate for your server in part 2 and finally the generated certificate is used in part 3 to run a secure HTTPS server.

- Part 1: run insecure HTTP server
- Part 2: generate server certificate
- Part 3: run secure HTTPS server

## Part 1: Running an insecure HTTP server

Clone the repository to your Pi:
```sh
git clone https://github.com/ThomasVliegen/tpm-demo.git
```
From your demo-tpm directory, build the http server by running:
```sh
make http_server
```
Next run the HTTP server using:
```sh
./build/http_server
```

This opens a webserver listening on port `11111`. Now perform a request to this server using your browser.

_Exercise: Can you intercept and read the response in plain text on the network using Wireshark?_


## TLS Dependencies

Part 2 & 3 use the WolfSSL and WolfTPM libraries. Go to your home directory (`cd ~`) to build and install these libraries.

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

## Part 2: Setting up the TPM and certificates

First of all, we need to generate a keypair on the TPM. Since only the TPM has access to the private key, we need to ask it to create a Certificate Signing Request (CSR) for us that we can send to a CA.

The `csr` tool creates a persistent key for you on index `0x81008123` if there does not exist any yet. Build and run the `csr` tool by running:
```sh
sudo make csr
sudo ./build/csr
```

This tool creates a CSR (`tpm-ecc-cert.csr`) and puts it in the `certs/` directory.

Then, we need a CA that can sign the TPM CSR. The `generate_certificates.sh` script first creates a new CA key pair and subsequently signs our TPM CSR with that CA:

```sh
./certs/generate_certificates.sh
```

We will use `ca-ecc-cert.pem` as the CA certificate and `server-ecc-cert.pem` as the certificate used by our TLS server.

## Part 3: Running a secure TLS server

Now we can run a TLS server that uses `server-ecc-cert.pem` to set up a TLS session. Build and run the TLS server by running:

```sh
sudo make tls_server
sudo ./build/tls_server
```

This opens a webserver running on port `11111`. Now perform a request to this server using Postman or your browser. If everything is set up correctly, these clients will complain that this connection is not trusted. For the purposes of this demo, you can ignore this warning and let them

_Exercise: Why do these tools warn you about this connection?_

_Exercise: Using Wireshark, find the point in the TLS handshake where this certificate is exchanged. Can you find the public key information in this certificate. Compare this public key to the one we created in the TPM. (Hint: `tpm2-tools` has some useful tools to interact with the TPM) (Hint 2: We created the key on index `0x81008123`)_

_Exercise: Can you make your client (Postman or browser) trust this connection and not display a security warning?_

## License

This repository makes use of the examples provided by [WolfSSL/WolfTPM](https://github.com/wolfSSL) distributed under the GPLv2 license.
