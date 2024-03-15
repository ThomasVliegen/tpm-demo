#pragma once

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <wolftpm/tpm2_socket.h>

#include <hal/tpm_io.h>

#include <wolfssl/ssl.h>

#include <stdio.h>

#include <netdb.h>

/* TLS Configuration */
#ifndef TLS_HOST
    #define TLS_HOST "localhost"
#endif
#ifndef TLS_PORT
    #define TLS_PORT 11111
#endif

#ifndef MAX_MSG_SZ
    #define MAX_MSG_SZ   (1 * 1024)
#endif
#ifndef TOTAL_MSG_SZ
    #define TOTAL_MSG_SZ (16 * 1024)
#endif

typedef struct SockIoCbCtx {
    int listenFd;
    int fd;
} SockIoCbCtx;

static inline int SockIORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    SockIoCbCtx* sockCtx = (SockIoCbCtx*)ctx;
    int recvd;

    (void)ssl;

    /* Receive message from socket */
    if ((recvd = (int)recv(sockCtx->fd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        printf("IO RECEIVE ERROR: ");
        switch (errno) {
        #if SOCKET_EAGAIN != SOCKET_EWOULDBLOCK
        case SOCKET_EAGAIN:
        #endif
        case SOCKET_EWOULDBLOCK:
            if (wolfSSL_get_using_nonblock(ssl)) {
                printf("would block\n");
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                printf("socket timeout\n");
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }
        case SOCKET_ECONNRESET:
            printf("connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case SOCKET_EINTR:
            printf("socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case SOCKET_ECONNREFUSED:
            printf("connection refused\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case SOCKET_ECONNABORTED:
            printf("connection aborted\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            printf("general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        printf("Connection closed\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    return recvd;
}

static inline int SockIOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    SockIoCbCtx* sockCtx = (SockIoCbCtx*)ctx;
    int sent;

    (void)ssl;

    /* Receive message from socket */
    if ((sent = (int)send(sockCtx->fd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        printf("IO SEND ERROR: ");
        switch (errno) {
        #if SOCKET_EAGAIN != SOCKET_EWOULDBLOCK
        case SOCKET_EAGAIN:
        #endif
        case SOCKET_EWOULDBLOCK:
            printf("would block\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case SOCKET_ECONNRESET:
            printf("connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case SOCKET_EINTR:
            printf("socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case SOCKET_EPIPE:
            printf("socket EPIPE\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            printf("general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (sent == 0) {
        printf("Connection closed\n");
        return 0;
    }

    return sent;
}

static inline int SetupSocketAndListen(SockIoCbCtx* sockIoCtx, word32 port)
{
    struct sockaddr_in servAddr;
    int optval  = 1;

    /* Setup server address */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockIoCtx->listenFd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: failed to create the socket\n");
        return -1;
    }

    /* allow reuse */
    if (setsockopt(sockIoCtx->listenFd, SOL_SOCKET, SO_REUSEADDR,
                   (void*)&optval, sizeof(optval)) == -1) {
        printf("setsockopt SO_REUSEADDR failed\n");
        return -1;
    }

    /* Connect to the server */
    if (bind(sockIoCtx->listenFd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        printf("ERROR: failed to bind\n");
        return -1;
    }

    if (listen(sockIoCtx->listenFd, 5) != 0) {
        printf("ERROR: failed to listen\n");
        return -1;
    }

    return 0;
}

static inline int SocketWaitClient(SockIoCbCtx* sockIoCtx)
{
    int connd;
    struct sockaddr_in clientAddr;
    XSOCKLENT          size = sizeof(clientAddr);

    if ((connd = accept(sockIoCtx->listenFd, (struct sockaddr*)&clientAddr, &size)) == -1) {
        printf("ERROR: failed to accept the connection\n\n");
        return -1;
    }
    sockIoCtx->fd = connd;
    return 0;
}

static inline int SetupSocketAndConnect(SockIoCbCtx* sockIoCtx, const char* host,
    word32 port)
{
    struct sockaddr_in servAddr;
    struct hostent* entry;

    /* Setup server address */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);

    /* Resolve host */
    entry = gethostbyname(host);
    if (entry) {
        XMEMCPY(&servAddr.sin_addr.s_addr, entry->h_addr_list[0],
            entry->h_length);
    }
    else {
        servAddr.sin_addr.s_addr = inet_addr(host);
    }

    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockIoCtx->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: failed to create the socket\n");
        return -1;
    }

    /* Connect to the server */
    if (connect(sockIoCtx->fd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        printf("ERROR: failed to connect\n");
        return -1;
    }

    return 0;
}

static inline void CloseAndCleanupSocket(SockIoCbCtx* sockIoCtx)
{
    if (sockIoCtx->fd != -1) {
        CloseSocket(sockIoCtx->fd);
        sockIoCtx->fd = -1;
    }
    if (sockIoCtx->listenFd != -1) {
        CloseSocket(sockIoCtx->listenFd);
        sockIoCtx->listenFd = -1;
    }
}

static inline int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    /* Verify Callback Arguments:
     * preverify:           1=Verify Okay, 0=Failure
     * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
     * store->error_depth:  Current Index
     * store->domain:       Subject CN as string (null term)
     * store->totalCerts:   Number of certs presented by peer
     * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
     * store->store:        WOLFSSL_X509_STORE with CA cert chain
     * store->store->cm:    WOLFSSL_CERT_MANAGER
     * store->ex_data:      The WOLFSSL object pointer
     */

    printf("In verification callback, error = %d, %s\n",
        store->error, wolfSSL_ERR_reason_error_string(store->error));
    printf("\tPeer certs: %d\n", store->totalCerts);
    printf("\tSubject's domain name at %d is %s\n",
        store->error_depth, store->domain);

    (void)preverify;

    /* If error indicate we are overriding it for testing purposes */
    if (store->error != 0) {
        printf("\tAllowing failed certificate check, testing only "
            "(shouldn't do this in production)\n");
    }

    /* A non-zero return code indicates failure override */
    return 1;
}
