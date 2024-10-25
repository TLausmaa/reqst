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
#include <openssl/err.h>
#include "req.h"

typedef struct reqst_opts {
    char* http_protocol_version;
    char* method;
    char* url;
    char* path;
    char* body;
    char* headers[10];
} reqst_opts;

typedef struct membuf {
    char* data;
    int   len;
} membuf;

typedef struct header {
    membuf* key;
    membuf* val;
} header;

typedef struct reqst_response {
    int     http_status_code;
    int     headers_num;
    int     headers_cap;
    header* headers;
    membuf* body;
} reqst_response;

reqst_response* request(reqst_opts* opts);

#ifdef REQST_IMPLEMENTATION 

#define MAX_READ 2048
#define PORT 443
#define DEBUG

#ifdef DEBUG
#define DPRINT(...) printf(__VA_ARGS__)
#else
#define DPRINT(...)
#endif

SSL_CTX *ssl_ctx = NULL;

reqst_response* alloc_new_response();
void debug_ssl();
int check_body_len(membuf* buf);
void deserialize_headers(reqst_response* response, membuf* orig_buf);
char* get_header_value(char* header_name, reqst_response* response);

void membuf_append(membuf* b, char* s, int n) {
    b->data = realloc(b->data, b->len + n + 1);
    memcpy(b->data + b->len, s, n);
    b->data[b->len + n] = '\0';
    b->len += n;
}

int init_openssl() {
    static char init = 0;
    if (init) {
        return 1;
    }

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
    debug_ssl();
    init = 1;
    return 1;
}

SSL* establish_ssl(int sockfd, char* hostname) {
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sockfd);

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);  
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_set_tlsext_host_name(ssl, hostname); // SNI (Server Name Indication)

    int conn_result_code = SSL_connect(ssl);
    if (conn_result_code < 1) {
        int reason = SSL_get_error(ssl, conn_result_code);
        DPRINT("SSL_connect failed with err code: %d, reason: %d\n", conn_result_code, reason);
        DPRINT("Printing error stack:\n");
        #ifdef DEBUG
        ERR_print_errors_fp(stderr);
        #endif
        DPRINT("End of error stack:\n");
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
        DPRINT("IP address for %s: %s\n", host, inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr));
        return inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr);
    } else {
        DPRINT("getaddrinfo() failed with err code: %d\n", addr_res);
        return NULL;
    }
}

void ssl_info_callback(const SSL *ssl, int where, int ret) {
    const char *str;
    int w = where & ~SSL_ST_MASK;
    
    if (w & SSL_ST_CONNECT) str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
    else str = "undefined";

    if (where & SSL_CB_LOOP) {
        DPRINT("%s: %s\n", str, SSL_state_string_long(ssl));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        DPRINT("SSL3 alert %s: %s: %s\n", str,
               SSL_alert_type_string_long(ret),
               SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0)
            DPRINT("%s: failed in %s\n", str, SSL_state_string_long(ssl));
        else if (ret < 0)
            DPRINT("%s: error in %s\n", str, SSL_state_string_long(ssl));
    }
}

void debug_ssl() {
    SSL_CTX_set_info_callback(ssl_ctx, &ssl_info_callback);
}

void build_request_payload(membuf* buf, reqst_opts* opts) {
    asprintf(&buf->data, "%s %s HTTP/%s\r\nHost: %s\r\n", 
        opts->method, 
        opts->path == NULL ? "/" : opts->path, 
        opts->http_protocol_version, 
        opts->url);
    buf->len = strlen(buf->data);

    for (int i = 0; i < 10; i++) {
        if (opts->headers[i] == NULL) {
            break;
        }
        membuf_append(buf, opts->headers[i], strlen(opts->headers[i]));
        membuf_append(buf, "\r\n", 2);
    }

    if (opts->body != NULL) {
        membuf_append(buf, "Content-Length: ", 16);
        char content_length[16];
        snprintf(content_length, 16, "%lu", strlen(opts->body));
        membuf_append(buf, content_length, strlen(content_length));
        membuf_append(buf, "\r\n\r\n", 4);
        membuf_append(buf, opts->body, strlen(opts->body));
    } else {
        membuf_append(buf, "\r\n", 2);
    }
    DPRINT("Request:###\n%s\n###\n", buf->data);
}

membuf* process_connection(int sockfd, reqst_opts* opts)
{
    SSL* ssl = establish_ssl(sockfd, opts->url);
    if (ssl == NULL) {
        DPRINT("Establishing SSL connection failed\n");
        return NULL;
    }

    membuf req = { .data = NULL, .len = 0 };
    build_request_payload(&req, opts);    

    int bytes_written = SSL_write(ssl, req.data, req.len);
    free(req.data);
    if (bytes_written < 1) {
        perror("ERROR writing to socket.");
        return NULL;
    }

    reqst_response* response = alloc_new_response();
    
    membuf* buf = (membuf*)malloc(sizeof(membuf));
    buf->data = NULL;
    buf->len = 0;

    char temp_buf[MAX_READ];
    int content_len_header_val = -1;
    int headers_checked = 0;

    for (;;) {
        bzero(temp_buf, sizeof(temp_buf));
        int num_read = 0;
        if ((num_read = SSL_read(ssl, temp_buf, MAX_READ)) < 1) {
            free(buf);
            free(response);
            perror("ERROR reading from socket.");
            break;
        }

        if (num_read > 0) {
            buf->data = realloc(buf->data, buf->len + num_read);
            memcpy(buf->data + buf->len, temp_buf, num_read);
            buf->len += num_read;

            DPRINT("Read %d bytes\n", num_read);

            int body_len = check_body_len(buf);
            if (body_len != -1) {
                if (headers_checked == 0) {
                    deserialize_headers(response, buf);
                    char* v = get_header_value("Content-Length", response);
                    if (v != NULL) {
                        content_len_header_val = atoi(v);
                    }
                    headers_checked = 1;
                }
                if (content_len_header_val != -1 && body_len < content_len_header_val) {
                    // We haven't received the whole body yet
                    continue; 
                }
            }

            // Content-Length header not found, read until we get 0 bytes
            if (num_read < MAX_READ) {
                // We've read all the data
                // except if the response happens to be exactly MAX_READ bytes
                // TODO: handle that case
                break;
            }
        } else if (num_read == 0) {
            DPRINT("SSL socket read operation not successful. Return code 0 from SSL_read.\n");
            break;
        } else if (num_read < 0) {
            int reason = SSL_get_error(ssl, num_read);
            DPRINT("SSL_read failed with err code: %d, reason: %d\n", num_read, reason);
            break;
        }
    }

    buf->data = realloc(buf->data, buf->len + 1);
    buf->data[buf->len] = '\0';
    buf->len++;
    DPRINT("Response data is:\n%s\n", buf->data);

    cleanup_openssl(ssl);
    return buf;
}

void deserialize_header(reqst_response* response, char* header_line) {
    char* header_save_ptr;
    int len      = strlen(header_line);
    char* key    = strtok_r(header_line, ":", &header_save_ptr);
    int key_len  = strlen(key);
    int val_len  = len - (key_len + 1);
    char* val    = (char*)malloc(val_len + 1);
    
    char* offset = header_line + key_len + 1; // skip the colon
    if (*offset == ' ') {                     // Usually there's a space after the colon
        offset++;
    }

    strncpy(val, offset, val_len);
    val[val_len] = '\0';

    if (key != NULL) {
        if (response->headers_num == response->headers_cap) {
            response->headers_cap += 5;
            response->headers = realloc(response->headers, sizeof(header) * response->headers_cap);
        }
        response->headers[response->headers_num].key       = (membuf*)malloc(sizeof(membuf));
        response->headers[response->headers_num].key->data = strdup(key);
        response->headers[response->headers_num].key->len  = key_len;
        response->headers[response->headers_num].val       = (membuf*)malloc(sizeof(membuf));
        response->headers[response->headers_num].val->data = val;
        response->headers[response->headers_num].val->len  = val_len - 1; // Exclude null terminator from length
        response->headers_num++;
    } else {
        DPRINT("Could not parse header from line: %s\n", header_line);
    }
}

int check_body_len(membuf* buf) {
    char* body_start = strstr(buf->data, "\r\n\r\n");
    if (body_start == NULL) {
        DPRINT("Could not find end of headers\n");
        return -1;
    }

    int headers_len = (body_start + 4) - buf->data; // 4 is the length of "\r\n\r\n"
    int body_len = buf->len - headers_len; 
    return body_len;
}

reqst_response* alloc_new_response() {
    reqst_response* response = (reqst_response*)malloc(sizeof(reqst_response));
    response->http_status_code = 200;
    response->headers = (header*)malloc(sizeof(header) * 2);
    response->headers_num = 0;
    response->headers_cap = 2;
    response->body = NULL;
    return response;
}

char* get_header_value(char* header_name, reqst_response* response) {
    for (int i = 0; i < response->headers_num; i++) {
        if (strcasecmp(response->headers[i].key->data, header_name) == 0) {
            return response->headers[i].val->data;
        }
    }
    return NULL;
}

void deserialize_headers(reqst_response* response, membuf* orig_buf) {
    if (orig_buf == NULL || orig_buf->data == NULL) {
        DPRINT("Response is NULL, nothing to deserialize\n");
        return;
    }

    membuf* buf = (membuf*)malloc(sizeof(membuf));
    buf->data = strdup(orig_buf->data);
    buf->len = orig_buf->len;
    
    char* line;
    char* line_save_ptr;
    char status_set = 0;
    char headers_set = 0;
    line = strtok_r(buf->data, "\n", &line_save_ptr);

    while (line != NULL) {
        if (line == NULL) {
            break;
        }

        // Parse status code
        if (status_set == 0 && strncmp(line, "HTTP/", 5) == 0) {
            char* status_save_ptr;
            char* status_code_str = strtok_r(line, " ", &status_save_ptr);
            status_code_str = strtok_r(NULL, " ", &status_save_ptr);
            status_set = 1;
            if (status_code_str != NULL) {
                response->http_status_code = atoi(status_code_str);
            } else {
                DPRINT("Could not parse status code from status header line\n");
            }
        // Parse "key: value" headers
        } else if (headers_set == 0 && strstr(line, ":") != NULL) {
            deserialize_header(response, line);
        } else if (headers_set == 0 && line[0] == '\r') {
            headers_set = 1;
        } else {
            // Encountered body section, stop parsing
            break;
        }
        
        line = strtok_r(NULL, "\n", &line_save_ptr);
    }

    free(buf->data);
    free(buf);
}

reqst_response* deserialize_response(membuf* buf) {
    if (buf == NULL || buf->data == NULL) {
        DPRINT("Response is NULL, nothing to deserialize\n");
        return NULL;
    }
    
    reqst_response* response = (reqst_response*)malloc(sizeof(reqst_response));
    response->http_status_code = 200;
    response->headers = (header*)malloc(sizeof(header) * 2);
    response->headers_num = 0;
    response->headers_cap = 2;
    response->body = NULL;

    char* line;
    char* line_save_ptr;
    char status_set = 0;
    char headers_set = 0;
    line = strtok_r(buf->data, "\n", &line_save_ptr);

    while (line != NULL) {
        if (line == NULL) {
            break;
        }

        // Parse status code
        if (status_set == 0 && strncmp(line, "HTTP/", 5) == 0) {
            char* status_save_ptr;
            char* status_code_str = strtok_r(line, " ", &status_save_ptr);
            status_code_str = strtok_r(NULL, " ", &status_save_ptr);
            status_set = 1;
            if (status_code_str != NULL) {
                response->http_status_code = atoi(status_code_str);
            } else {
                DPRINT("Could not parse status code from status header line\n");
            }
        // Parse "key: value" headers
        } else if (headers_set == 0 && strstr(line, ":") != NULL) {
            deserialize_header(response, line);
        } else if (headers_set == 0 && line[0] == '\r') {
            headers_set = 1;
        } else {
            if (response->body == NULL) {
                response->body = (membuf*)malloc(sizeof(membuf));
                response->body->data = strdup(line);
                response->body->len = strlen(line);
            } else {
                int line_len = strlen(line);
                response->body->data = realloc(response->body->data, response->body->len + line_len);
                memcpy(response->body->data + response->body->len, line, line_len);
                response->body->len += line_len;
            }
        }
        
        line = strtok_r(NULL, "\n", &line_save_ptr);
    }

    free(buf->data);
    free(buf);
    return response;
}

reqst_response* request(reqst_opts* opts) {
    init_openssl();

    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        DPRINT("socket creation failed...\n");
        exit(0);
    } else {
        DPRINT("Socket successfully created..\n");
    }
    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(get_addr(opts->url));
    servaddr.sin_port = htons(PORT);

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        DPRINT("connection with the server failed...\n");
        exit(0);
    } else {
        DPRINT("connected to the server..\n");
    }

    membuf* res = process_connection(sockfd, opts);

    close(sockfd);

    return deserialize_response(res);
}

#endif // REQST_IMPLEMENTATION
