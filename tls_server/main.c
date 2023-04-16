
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include "hal/tpm_io.h"

#include "common/ecc_key.h"
#include "common/socket.h"

#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdbool.h>

int TlsServer(void* userCtx, [[maybe_unused]] int argc, [[maybe_unused]] char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;

    WOLFTPM2_KEY eccKey;
    ecc_key wolfEccKey;

    TpmCryptoDevCtx tpmCtx;
    SockIoCbCtx sockIoCtx;
    int tpmDevId;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const char webServerMsg[] =
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html\n"
        "Connection: close\n"
        "\n"
        "<html><head><title>Well done!</title></head>\n"
        "<body>This page is served over TLS with the private key guarded by a TPM!</body></html>\n";
    char msg[MAX_MSG_SZ];
    int msgSz = 0;
    WOLFTPM2_SESSION tpmSession;
    TPMT_PUBLIC publicTemplate;

    // Initialize
    XMEMSET(&storageKey, 0, sizeof(storageKey));
    XMEMSET(&sockIoCtx, 0, sizeof(sockIoCtx));
    sockIoCtx.fd = -1;
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));

    XMEMSET(&eccKey, 0, sizeof(eccKey));
    XMEMSET(&wolfEccKey, 0, sizeof(wolfEccKey));

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    // Initialize TPM context
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0)
    {
        wolfSSL_Cleanup();
        return rc;
    }

    /* Setup the wolf crypto device callback */
    tpmCtx.eccKey = &eccKey;
    tpmCtx.storageKey = &storageKey;
    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx, &tpmDevId);
    if (rc != 0) goto exit;

    /* See if primary storage key already exists */
    // rc = getPrimaryStoragekey(&dev, &storageKey, TPM_ALG_RSA);
    // if (rc != 0) goto exit;

    /* Create/Load ECC key for TLS authentication */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
            TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;

    rc = GetPrimaryECCKey(&dev, &eccKey, &wolfEccKey, tpmDevId, &publicTemplate);
    if (rc != 0) goto exit;

    /* Setup the WOLFSSL context (factory)
     * Use highest version, allow downgrade */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL)
    {
        rc = MEMORY_E; goto exit;
    }

    /* Setup DevID */
    wolfSSL_CTX_SetDevId(ctx, tpmDevId);

    /* Setup IO Callbacks */
    wolfSSL_CTX_SetIORecv(ctx, SockIORecv);
    wolfSSL_CTX_SetIOSend(ctx, SockIOSend);

    /* Server certificate validation */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);

    /* Load CA Certificates */
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certs/ca-ecc-cert.pem", 0) != WOLFSSL_SUCCESS)
    {
        printf("Error loading ca-ecc-cert.pem cert\n");
        goto exit;
    }

    byte der[256];
    word32 derSz = sizeof(der);

    printf("Loading ECC certificate and public key\n");

    if ((rc = wolfSSL_CTX_use_certificate_file(ctx, "./certs/server-ecc-cert.pem", WOLFSSL_FILETYPE_PEM))
            != WOLFSSL_SUCCESS)
    {
        printf("Error loading ECC client cert\n");
        goto exit;
    }

    rc = wc_EccPublicKeyToDer(&wolfEccKey, der, derSz, 1);
    if (rc < 0)
    {
        printf("Failed to export ECC public key!\n");
        goto exit;
    }
    derSz = rc;
    rc = 0;

    /* Private key only exists on the TPM and crypto callbacks are used for
        * signing. Public key is required to enable TLS server auth.
        * This API accepts public keys when crypto callbacks are enabled */
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, derSz,
                                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("Failed to set ECC key!\r\n");
        goto exit;
    }

    // Infinite loop of accepting client connections
    while (1)
    {
    	// Create wolfSSL session
    	if ((ssl = wolfSSL_new(ctx)) == NULL) {
        	rc = wolfSSL_get_error(ssl, 0);
        	goto cleanup;
    	}

    	rc = SetupSocketAndListen(&sockIoCtx, TLS_PORT);
    	if (rc != 0) goto cleanup;

        // Setup callbacks
    	wolfSSL_SetIOReadCtx(ssl, &sockIoCtx);
    	wolfSSL_SetIOWriteCtx(ssl, &sockIoCtx);
    	rc = SocketWaitClient(&sockIoCtx);
    	if (rc != 0) goto cleanup;

        // Accept connection
        do
        {
            rc = wolfSSL_accept(ssl);
            if (rc != WOLFSSL_SUCCESS)
            {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_READ || rc == WOLFSSL_ERROR_WANT_WRITE);

        if (rc != WOLFSSL_SUCCESS) goto cleanup;

        // Read request
        do
        {
            rc = wolfSSL_read(ssl, msg, sizeof(msg));
            if (rc < 0)
            {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_READ);

        if (rc >= 0)
        {
            msgSz = rc;
            /* null terminate */
            if (msgSz >= (int)sizeof(msg))
                msgSz = (int)sizeof(msg) - 1;
            msg[msgSz] = '\0';
            printf("Read (%d): %s\n", msgSz, msg);
            rc = 0;
        }
        if (rc != 0) goto cleanup;

        // Write response
        msgSz = sizeof(webServerMsg);
        XMEMCPY(msg, webServerMsg, msgSz);
        do
        {
            rc = wolfSSL_write(ssl, msg, msgSz);
            if (rc != msgSz) {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_WRITE);

        if (rc >= 0)
        {
            msgSz =  rc;
            printf("Write (%d): %s\n", msgSz, msg);
            rc = 0;
        }

cleanup:
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        CloseAndCleanupSocket(&sockIoCtx);
    }

exit:

    if (rc != 0)
    {
        printf("Failure %d (0x%x): %s\n", rc, rc, wolfTPM2_GetRCString(rc));
    }


    wolfSSL_CTX_free(ctx);

    wolfTPM2_UnloadHandle(&dev, &storageKey.handle);
    wc_ecc_free(&wolfEccKey);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

int main(int argc, char* argv[])
{
    int rc;

    rc = TlsServer(NULL, argc, argv);

    return rc;
}
