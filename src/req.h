#pragma once

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
#include "req.h"

typedef struct req_opts {
    char* http_protocol_version;
    char* method;
    char* url;
} req_opts;

typedef struct serv_response {
    int  http_status_code;
} serv_response;

serv_response* request(req_opts* opts);

#ifdef SERV_REQ_IMPLEMENTATION

#define MAX_READ 2048
#define PORT 443

typedef struct membuf {
    char* data;
    int   len;
} membuf;

SSL_CTX *ssl_ctx = NULL;

int init_openssl() {
    static char init = 0;
    if (init) {
        return 1;
    }

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
    init = 1;
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
        printf("IP address for %s: %s\n", host, inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr));
        return inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr);
    } else {
        printf("getaddrinfo() failed with err code: %d\n", addr_res);
        return NULL;
    }
}

membuf* process_connection(int sockfd, req_opts* opts)
{
    SSL* ssl = establish_ssl(sockfd);
    if (ssl == NULL) {
        printf("Establishing SSL connection failed\n");
        return NULL;
    }

    char req[256];
    snprintf(req, 256, "%s / HTTP/%s\r\nHost: %s\r\n\r\n", opts->http_protocol_version, opts->method, opts->url);
    int n = 0;

    if ((n = SSL_write(ssl, req, sizeof(req))) < 1) {
        perror("ERROR writing to socket.");
        return NULL;
    }

    membuf* res = (membuf*)malloc(sizeof(membuf));
    res->data = NULL;
    res->len = 0;

    char buff[MAX_READ];

    for (;;) {
        bzero(buff, sizeof(buff));
        int num_read = 0;
        if ((num_read = SSL_read(ssl, buff, MAX_READ)) < 1) {
            perror("ERROR reading from socket.");
            break;
        }

        if (num_read > 0) {
            res->data = realloc(res->data, res->len + num_read);
            memcpy(res->data + res->len, buff, num_read);
            res->len += num_read;

            if (num_read < MAX_READ) {
                // We've read all the data
                // except if the response happens to be exactly MAX_READ bytes
                // TODO: handle that case
                break;
            }
        } else if (num_read == 0) {
            printf("SSL socket read operation not successful. Return code 0 from SSL_read.\n");
            break;
        } else if (num_read < 0) {
            int reason = SSL_get_error(ssl, num_read);
            printf("SSL_read failed with err code: %d, reason: %d\n", num_read, reason);
            break;
        }
    }

    res->data = realloc(res->data, res->len + 1);
    res->data[res->len] = '\0';
    res->len++;
    printf("final data is:\n%s\n", res->data);

    cleanup_openssl(ssl);
    return res;
}

serv_response* deserialize_response(membuf* res) {
    // Handle reading the response here
    printf("Deserialize now\n");
    if (res == NULL) {
        printf("Response is NULL, nothing to deserialize\n");
    }
    return NULL;
}

serv_response* request(req_opts* opts) {
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
    servaddr.sin_addr.s_addr = inet_addr(get_addr(opts->url));
    servaddr.sin_port = htons(PORT);

    // connect the client socket to server socket
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    } else {
        printf("connected to the server..\n");
    }

    membuf* res = process_connection(sockfd, opts);

    // close the socket
    close(sockfd);

    return deserialize_response(res);
}

#endif // SERV_REQ_IMPLEMENTATION
