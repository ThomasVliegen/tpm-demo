#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LISTENQ_SIZE  (int32_t) 16          /* max pending connections in queue */
#define RSP_BUFFER_SIZE (int32_t) 8192      /* max length of a line */
#define RCV_BUFFER_SIZE (int32_t) 1024
#define USERNAME "admin"
#define PASSWORD "password123"

// function declarations
int32_t open_listenfd(int32_t port);
static void log_access(const char* status_code, struct sockaddr_in* c_addr);
static void process(int32_t fd, struct sockaddr_in* clientaddr);
static void send_page(int32_t fd, struct sockaddr_in* clientaddr, const char* page, const char* status_code);
static void send_not_found_page(int32_t fd, struct sockaddr_in* clientaddr);
static void send_unauthorized_page(int32_t fd, struct sockaddr_in* clientaddr);
static void send_response(int32_t fd, void* usrbuf, size_t n);
static void handle_login(int32_t client_sock, struct sockaddr_in* clientaddr, char* body);
static const char* read_file();

int32_t open_listenfd(int32_t port){
    int32_t listenfd, optval=1;
    struct sockaddr_in serveraddr;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval , sizeof(int32_t)) < 0)
        return -1;

    /* Listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);
    if (bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    if (listen(listenfd, LISTENQ_SIZE) < 0)
        return -1;
    return listenfd;
}

static void log_access(const char* status_code, struct sockaddr_in* c_addr){
    printf("%s:%d - %s\n", inet_ntoa(c_addr->sin_addr),
           ntohs(c_addr->sin_port), status_code);
}

static void process(int32_t fd, struct sockaddr_in* clientaddr){
    char request_buffer[RCV_BUFFER_SIZE];
    printf("accept request, fd is %d, pid is %d\n", fd, getpid());
    int32_t read_size = recv(fd, request_buffer, RCV_BUFFER_SIZE - 1, 0);

    if (read_size > 0) {
        request_buffer[read_size] = '\0';
        if (strstr(request_buffer, "GET /") != NULL) {
            const char *content = read_file("http_server/pages/login.html");
            if (content == NULL)
                send_not_found_page(fd, clientaddr);
            else
                send_page(fd, clientaddr, content, "200 OK");
            free((char *)content);   
        } else if (strstr(request_buffer, "POST /login") != NULL) {
            // Find the start of the body
            char *body = strstr(request_buffer, "\r\n\r\n") + 4;
            handle_login(fd, clientaddr, body);
        } else {
            send_not_found_page(fd, clientaddr);
        }
    }
    close(fd);
}

static void send_page(int32_t fd, struct sockaddr_in* clientaddr, const char* content, const char* status_code)
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
    send_response(fd, response_buf, strlen(response_buf));
    log_access(status_code, clientaddr);
}

static void send_not_found_page(int32_t fd, struct sockaddr_in* clientaddr)
{
    const char* status_code = "404 Not Found";
    const char* response_buf = "<html><body><h1>404 Not Found</h1></body></html>";
    send_page(fd, clientaddr, response_buf, status_code);
}

static void send_unauthorized_page(int32_t fd, struct sockaddr_in* clientaddr)
{
    const char* status_code = "401 Unauthorized";
    const char* response_buf = "<html><body><h1>401 Unauthorized</h1></body></html>";
    send_page(fd, clientaddr, response_buf, status_code);
}

static void send_response(int32_t fd, void* usrbuf, size_t n){
    size_t nleft = n;
    ssize_t nwritten;
    char *bufp = usrbuf;

    while (nleft > 0){
        if ((nwritten = write(fd, bufp, nleft)) <= 0){
            if (errno == EINTR)  /* interrupted by sig handler return */
                nwritten = 0;    /* and call write() again */
            else
                return;          /* errorno set by write() */
        }
        nleft -= nwritten;
        bufp += nwritten;
    }
}

static void handle_login(int32_t client_sock, struct sockaddr_in* clientaddr, char *body) {
    char username[128] = {0}, password[128] = {0};

    sscanf(body, "username=%127[^&]&password=%127s", username, password);
    printf("Received:\nUsername: %s\nPassword: %s\n", username, password);

    // Check credentials
    if (strcmp(username, USERNAME) == 0 && strcmp(password, PASSWORD) == 0) {
        const char *content = read_file("http_server/pages/dashboard.html");
        if (content == NULL)
            send_not_found_page(client_sock, clientaddr);
        else
            send_page(client_sock, clientaddr, content, "200 OK");
        free((char *)content);
    } else {
        send_unauthorized_page(client_sock, clientaddr);
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

int32_t main(int32_t argc, char** argv){
    struct sockaddr_in clientaddr;
    socklen_t clientlen = sizeof clientaddr;
    int32_t default_port = 11111;
    int32_t listenfd, connfd;

    listenfd = open_listenfd(default_port);
    if (listenfd > 0) {
        printf("listen on port %d, fd is %d\n", default_port, listenfd);
    } else {
        perror("ERROR");
        exit(listenfd);
    }
    // Ignore SIGPIPE signal, so if browser cancels the request, it
    // won't kill the whole process.
    signal(SIGPIPE, SIG_IGN);

    while(1){
        connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        process(connfd, &clientaddr);
    }

    close(listenfd);

    return 0;
}
