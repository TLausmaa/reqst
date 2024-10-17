#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> 
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h> 
#include <openssl/ssl.h>

#define MAX_READ 2048
#define PORT 443

// #define SA struct sockaddr

typedef struct response {
    char* data;
    int len;
} response;

SSL_CTX *ssl_ctx = NULL;

int init_openssl() {
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
    return 1;
}

SSL* establish_ssl(int sockfd) {
    // create an SSL connection and attach it to the socket
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sockfd);

    // perform the SSL/TLS handshake with the server - when on the
    // server side, this would use SSL_accept()
    int conn_result_code = SSL_connect(ssl);
    if (conn_result_code < 1) {
        int reason = SSL_get_error(ssl, conn_result_code);
        printf("SSL_connect failed with err code: %d, reason: %d\n", conn_result_code, reason);
        return NULL;
    }

    // now proceed with HTTP traffic, using SSL_read instead of recv() and
    // SSL_write instead of send(), and SSL_shutdown/SSL_free before close()
    return ssl;
}

void cleanup_openssl(SSL* ssl) {
    if (ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
    }
    SSL_free(ssl);
}

char* get_addr(const char* host) {
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    int addr_res = getaddrinfo(host, NULL, &hints, &res);
    if (addr_res == 0) {
        printf("getaddrinfo() success\n");
        printf("IP address: %s\n", inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr));
        return inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr);
    } else {
        printf("getaddrinfo() failed with err code: %d\n", addr_res);
        return NULL;
    }
}

void process_connection(int sockfd)
{
    SSL* ssl = establish_ssl(sockfd);
    if (ssl == NULL) {
        printf("establish_ssl() failed\n");
        return;
    }

    // char req[256] = "GET /api/users/2 HTTP/1.1\r\nHost: reqres.in\r\n\r\n";
    char req[256] = "GET / HTTP/1.1\r\nHost: news.ycombinator.com\r\n\r\n"; // HTTP/2 maybe ??? 
    char buff[MAX_READ];
    
    // write(sockfd, req, sizeof(req));
    int n = 0;
    if ((n = SSL_write(ssl, req, sizeof(req))) < 1) {
        perror("ERROR writing to socket.");
        return;
    }

    response res;
    res.data = NULL;
    res.len = 0;

    for (;;) {
        // int len = 0;
        // ioctl(sockfd, FIONREAD, &len);
        // printf("--- Bytes available to read: %d\n", len);
        printf("reading...\n");

        bzero(buff, sizeof(buff));
        // int num_read = read(sockfd, buff, sizeof(buff));
        int num_read = 0;
        if ((num_read = SSL_read(ssl, buff, MAX_READ)) < 1) {
            perror("ERROR reading from socket.");
            break;
        }

        if (num_read > 0) {
            printf("reallocing...\n");
            res.data = realloc(res.data, res.len + num_read);
            memcpy(res.data + res.len, buff, num_read);
            res.len += num_read;
        }

        if (num_read == 0) {
            printf("Server closed connection\n");
            break;
        }
    }

    res.data = realloc(res.data, res.len + 1);
    res.data[res.len] = '\0';
    res.len++;
    printf("final data is:\n%s\n", res.data);

    // clean up
    free(res.data);
    cleanup_openssl(ssl);
}

int main()
{
    init_openssl();

    int sockfd;
    struct sockaddr_in servaddr;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    } else {
        printf("Socket successfully created..\n");
    }
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(get_addr("news.ycombinator.com"));
    servaddr.sin_port = htons(PORT);

    // connect the client socket to server socket
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    } else {
        printf("connected to the server..\n");
    }

    process_connection(sockfd);

    // close the socket
    close(sockfd);
}
