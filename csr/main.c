#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <hal/tpm_io.h>

#include <common/ecc_key.h>

static const char* sEccCsrFile = "./certs/tpm-ecc-cert.csr";

static int TpmCsrGenerate(WOLFTPM2_DEV* dev, int keyType, WOLFTPM2_KEY* key, const char* outputPemFile, int devId)
{
    int rc;
    const char* subject = "/C=NL/ST=Noord-Brabant/L='s-Hertogenbosch/O=DemoOrg/OU=TPM Demo/CN=www.example.com";
    const char* keyUsage = "serverAuth,clientAuth,codeSigning,"
                           "emailProtection,timeStamping,OCSPSigning";
    WOLFTPM2_BUFFER output;

    WOLFTPM2_CSR* csr = wolfTPM2_NewCSR();
    if (csr == NULL)
    {
        return MEMORY_E;
    }

    output.size = (int)sizeof(output.buffer);
    rc = wolfTPM2_CSR_SetSubject(dev, csr, subject);
    if (rc == 0)
    {
        rc = wolfTPM2_CSR_SetKeyUsage(dev, csr, keyUsage);
    }
    if (rc == 0)
    {
        rc = wolfTPM2_CSR_MakeAndSign_ex(dev, csr, key, CTC_FILETYPE_PEM,
            output.buffer, output.size, 0, false, devId);
    }

    if (rc >= 0)
    {
        output.size = rc;
        printf("Generated/Signed Cert (PEM %d)\n", output.size);
        FILE* pemFile = fopen(outputPemFile, "wb");
        if (pemFile)
        {
            rc = (int)fwrite(output.buffer, 1, output.size, pemFile);
            fclose(pemFile);
            rc = (rc == output.size) ? 0 : -1;
            if (rc == 0)
            {
                printf("Saved to %s\n", outputPemFile);
            }
        }
        printf("%s\n", (char*)output.buffer);
    }

    (void)outputPemFile;
    wolfTPM2_FreeCSR(csr);

    return rc;
}

int CreateCSR(int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY key;
    TpmCryptoDevCtx tpmCtx;
    int tpmDevId;
    TPMT_PUBLIC publicTemplate;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));

    // Init TPM2 device
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != 0) return rc;

    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx, &tpmDevId);

    if (rc == 0)
    {
        tpmCtx.eccKey = &key;
        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        if (rc == 0) {
            rc = GetPrimaryECCKey(&dev, &key, NULL, tpmDevId, &publicTemplate);
        }
        if (rc == 0) {
            rc = TpmCsrGenerate(&dev, ECC_TYPE, &key, sEccCsrFile, tpmDevId);
        }
        wolfTPM2_UnloadHandle(&dev, &key.handle);
    }

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_Cleanup(&dev);

    return rc;
}

int main(int argc, char *argv[])
{
    int rc;

    rc = CreateCSR(argc, argv);

    return rc;
}
