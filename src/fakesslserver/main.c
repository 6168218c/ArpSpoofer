#include "sslutil.h"
#include "winsock2.h"
#include "iphlpapi.h"
#include "wininet.h"
#include "openssl/applink.c"

#define FAILFAST(function, msg)                  \
    perror("Error occurred in [" #function "]"); \
    exit(EXIT_FAILURE);

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

int main()
{
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

int parse_http_method(char *start)
{
    char *p = start;
    for (; *p != ' ' && *p != '\t'; p++)
    {
    }
    if (strncmp(start, 'GET', p - start - 1) == 0) // GET
    {
    }
    else if (strncmp(start, 'POST', p - start - 1) == 0) // POST
    {
    }
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
        if (err == 0) // Not fatal errors
        {
        size_t readBytes = 0;
        char *content_start = NULL;
        int content_length = 0;
        if (SSL_read_ex(ssl, buffer, BUF_SIZE, &readBytes) >= 0)
        {
            if (readBytes > 0) // we should have read header
            {
                int lineEndCnt = 0;
                for (char *pos = buffer; pos < buffer + BUF_SIZE; pos++)
                {
                    if (*pos == '\r' && *(pos + 1) == '\n') // lineEnd
                    {
                        ++lineEndCnt;
                        if (lineEndCnt == 1) // first line
                        {
                        }
                    }
                }
                memset(buffer, 0, BUF_SIZE);
            }
        }
        }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(client);
}