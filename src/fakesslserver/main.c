#include "sslutil.h"
#include "winsock2.h"
#include "openssl/applink.c"

#define FAILFAST(function, msg)                       \
    perror("Error occurred in [" #function "]:" msg); \
    exit(EXIT_FAILURE);
#define LOGERROR(category, msg) perror("Error occurred in [" #category "]" msg);

int create_socket(uint16_t port)
{
    int skt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (skt < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(skt, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        FAILFAST(create_socket, "Unable to bind");
    }

    if (listen(skt, SOMAXCONN) == SOCKET_ERROR)
    {
        FAILFAST(create_socket, "Unable to listen");
    }

    return skt;
}

void handleRequest(int client, SSL *ssl);

int main(int argc, char **argv)
{
    FILE *tst = fopen("cert.pem", "rb");
    fclose(tst);
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
    {
        perror("WSAStartup error");
        WSACleanup();
        exit(EXIT_FAILURE);
    }
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = ssl_create_context();
    ssl_configure_context(ctx);

    int sock = create_socket(27013);

    printf("Listening on port 27013\n");
    while (1) // handle connection
    {
        struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *ssl;
        int client = accept(sock, (SOCKADDR *)&addr, &len);
        if (client < 0)
        {
            FAILFAST(main, "Unable to accept");
        }
        ssl = SSL_new(ctx);
        handleRequest(client, ssl);
    }

    SSL_CTX_free(ctx);
    WSACleanup();
}

void handleRequest(int client, SSL *ssl)
{
    SSL_set_fd(ssl, client);
    int err = 0;
    int ret = 0;
    const int BUF_SIZE = 8192;
    char *buffer = malloc(BUF_SIZE);
    memset(buffer, 0, BUF_SIZE);

    if (ret = SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        err = SSL_get_error(ssl, ret);
    }
    if (err != 0) // fatal errors
    {
        if (err != SSL_ERROR_SYSCALL)
            SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }
    int serverSocket = 0;
    size_t readBytes = 0;
    char *host = NULL;
    int content_length = 0;
    if (ret = SSL_read_ex(ssl, buffer, BUF_SIZE, &readBytes) >= 0)
    {
        if (readBytes > 0) // we should have read header
        {
            char *lineBegin = buffer;
            for (char *pos = buffer; pos < buffer + BUF_SIZE - 3; pos++)
            {
                if (*pos == '\r' && *(pos + 1) == '\n') // lineEnd
                {
                    char *nextStart = pos + 2;
                    if (lineBegin)
                    {
                        if (strncmp(lineBegin, "Host", 4) == 0) // HOST
                        {
                            host = malloc(pos - lineBegin);
                            memset(host, 0, pos - lineBegin);
                            memcpy(host, lineBegin + 5, pos - lineBegin + 4);
                            // we found what we want, break
                            break;
                        }
                    }
                    if (*nextStart == '\r' && *(nextStart + 1) == '\n') // header end
                        break;
                    lineBegin = pos + 1;
                }
            }
            // Retransmit the socket to
            memset(buffer, 0, BUF_SIZE);
        }
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr;
    struct hostent *remoteHost = gethostbyname(host);
    if (remoteHost == NULL || remoteHost->h_addrtype != AF_INET || remoteHost->h_addr_list[0] == 0)
    {
        LOGERROR(gethostbyname, "Unable to resolve remote host");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }
    addr.sin_addr.s_addr = *(u_long *)remoteHost->h_addr_list[0];
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SSL_CTX *subContext = SSL_CTX_new(TLS_client_method());
    SSL *subSsl = SSL_new(subContext);
    if (serverSocket < 0)
    {
        perror("Unable to create socket");
        SSL_free(subSsl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }
    if (connect(serverSocket, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        LOGERROR(handleRequest, "Unable to bind");
        SSL_free(subSsl);
        closesocket(serverSocket);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }
    SSL_set_fd(subSsl, serverSocket);
    if (ret = SSL_connect(subSsl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        err = SSL_get_error(subSsl, ret);
        if (err != SSL_ERROR_SYSCALL)
            SSL_shutdown(subSsl);
        SSL_free(subSsl);
        closesocket(serverSocket);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
        return;
    }
    ret = SSL_write(subSsl, buffer, readBytes);
    while (ret = SSL_read_ex(ssl, buffer, BUF_SIZE, &readBytes) >= 0)
    {
        ret = SSL_write(subSsl,buffer,readBytes);
    }
    while (ret = SSL_read_ex(subSsl, buffer, BUF_SIZE, &readBytes) >= 0)
    {
        ret = SSL_write(ssl,buffer,readBytes);
    }

    SSL_shutdown(subSsl);
    SSL_free(subSsl);
    closesocket(serverSocket);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(client);
}