
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include "hal/tpm_io.h"

#include "common/ecc_key.h"
#include "common/socket.h"

#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdbool.h>
#include <signal.h>

#define TLS_PORT 11111
#define RSP_BUFFER_SIZE (int32_t) 8192      /* max length of a line */
#define RCV_BUFFER_SIZE (int32_t) 1024
#define USERNAME "admin"
#define PASSWORD "password123"

// function declarations
static void process(WOLFSSL* ssl);
static void send_page(WOLFSSL* ssl, const char* page, const char* status_code);
static void send_not_found_page(WOLFSSL* ssl);
static void send_unauthorized_page(WOLFSSL* ssl);
static void send_bad_request_page(WOLFSSL* ssl);
static int send_response(WOLFSSL* ssl, void* usrbuf, size_t n);
static void handle_login(WOLFSSL* ssl, char* body);
static const char* read_file(const char *filename);

static void process(WOLFSSL* ssl)
{
    char request_buffer[RCV_BUFFER_SIZE];
    int rc = 0;
    do
    {
        rc = wolfSSL_read(ssl, request_buffer, sizeof(request_buffer));
        if (rc < 0)
        {
            rc = wolfSSL_get_error(ssl, 0);
        }
    } while (rc == WOLFSSL_ERROR_WANT_READ);
    
    if (rc > 0) {
        const int32_t request_size = rc;
        request_buffer[request_size] = '\0';
        printf("Read (%d): %s\n", request_size, request_buffer);
        if (strstr(request_buffer, "GET /") != NULL) {
            const char *content = read_file("http_server/pages/login.html");
            if (content == NULL)
                send_not_found_page(ssl);
            else
                send_page(ssl, content, "200 OK");
            free((char *)content);   
        } else if (strstr(request_buffer, "POST /login") != NULL) {
            printf("login request received\n");
            // Find the start of the body
            char *body = strstr(request_buffer, "\r\n\r\n") + 4;
            handle_login(ssl, body);
        } else {
            send_bad_request_page(ssl);
        }
    }
}

static void send_page(WOLFSSL* ssl, const char* content, const char* status_code)
{
    char response_buf[RSP_BUFFER_SIZE];
    size_t content_length = strlen(content);
    snprintf(response_buf, sizeof(response_buf), 
            "HTTP/1.1 %s\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n"
            "Content-Length: %zu\r\n"
            "\r\n"
            "%s", status_code, content_length, content);
    send_response(ssl, response_buf, sizeof(response_buf));
}

static void send_not_found_page(WOLFSSL* ssl)
{
    const char* status_code = "404 Not Found";
    const char* response_buf = "<html><body><h1>404 Not Found</h1></body></html>";
    send_page(ssl, response_buf, status_code);
}

static void send_unauthorized_page(WOLFSSL* ssl)
{
    const char* status_code = "401 Unauthorized";
    const char* response_buf = "<html><body><h1>401 Unauthorized</h1></body></html>";
    send_page(ssl, response_buf, status_code);
}

static void send_bad_request_page(WOLFSSL* ssl)
{
    const char* status_code = "400 Bad Request";
    const char* response_buf = "<html><body><h1>400 Bad Request</h1></body></html>";
    send_page(ssl, response_buf, status_code);
}

static int send_response(WOLFSSL* ssl, void* usrbuf, size_t n)
{
    int rc = 0;
    do
    {
        rc = wolfSSL_write(ssl, usrbuf, n);
        if (rc != n) {
            rc = wolfSSL_get_error(ssl, 0);
        }
    } while (rc == WOLFSSL_ERROR_WANT_WRITE);
    return rc;
}

static void handle_login(WOLFSSL* ssl, char *body) {
    char username[128] = {0}, password[128] = {0};

    sscanf(body, "username=%127[^&]&password=%127s", username, password);
    printf("Received:\nUsername: %s\nPassword: %s\n", username, password);

    // Check credentials
    if (strcmp(username, USERNAME) == 0 && strcmp(password, PASSWORD) == 0) {
        const char *content = read_file("http_server/pages/dashboard.html");
        if (content == NULL)
            send_not_found_page(ssl);
        else
            send_page(ssl, content, "200 OK");
        free((char *)content);
    } else {
        send_unauthorized_page(ssl);
    }
}

static const char *read_file(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        perror("Unable to open file");
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        perror("Unable to find end of file");
        fclose(file);
        return NULL;
    }

    long filesize = ftell(file);
    if (filesize == -1)
    {
        perror("Unable to determine filesize");
        rewind(file);
        fclose(file);
        return NULL;
    }
    rewind(file);

    char *buffer = (char *)malloc((filesize + 1) * sizeof(char));
    if (buffer == NULL)
    {
        perror("Unable to allocate memory");
        fclose(file);
        return NULL;
    }

    if ((long)fread(buffer, 1, filesize, file) < filesize)
    {
        fprintf(stderr, "Error: Failed to read file\n");
        fclose(file);
        return NULL;
    }

    buffer[filesize] = '\0';

    fclose(file);
    return buffer;
}

int TlsServer(void* userCtx, [[maybe_unused]] int argc, [[maybe_unused]] char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev = {0};
    WOLFTPM2_KEY storageKey = {0};

    WOLFTPM2_KEY eccKey = {0};
    ecc_key wolfEccKey = {0};

    TpmCryptoDevCtx tpmCtx = {0};
    SockIoCbCtx sockIoCtx = {0};
    int tpmDevId;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    WOLFTPM2_SESSION tpmSession = {0};
    TPMT_PUBLIC publicTemplate;

    // Initialize
    sockIoCtx.fd = -1;

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

        // Process
        process(ssl);

cleanup:
        printf("Cleanup reached!\n");
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        CloseAndCleanupSocket(&sockIoCtx);
    }

exit:
    printf("Exit reached!\n");
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
    // Ignore SIGPIPE signal, so if browser cancels the request, it
    // won't kill the whole process.
    signal(SIGPIPE, SIG_IGN);
    int rc;

    rc = TlsServer(NULL, argc, argv);

    return rc;
}
