#include <stdio.h>
#define REQST_IMPLEMENTATION
#include "req.h"

//#define GET
//#define POST
//#define GET_USERS
#define GET_GITHUB_GISTS

int main(int argc, char** argv)
{
    #ifdef GET
    reqst_opts opts = { 
        .http_protocol_version = "1.1",
        .method = "GET",
        .url = "reqres.in",
        .path = "/api/users/2"
    };

    reqst_response* res = request(&opts);

    if (res == NULL) {
        printf("Error occurred when handling request: NULL result\n");
        return 1;
    }

    printf("HTTP status code was: %d\n", res->http_status_code);

    for (int i = 0; i < res->headers_num; i++) {
        printf("Header %d: %s:%s\n", i+1, res->headers[i].key->data, res->headers[i].val->data);
    }

    printf("Body: %s\n", res->body->data);
    #endif

    #ifdef POST
    reqst_opts opts = {
        .http_protocol_version = "1.1",
        .method = "POST",
        .url = "reqres.in",
        .path = "/api/users",
        .body = "{\"name\": \"morpheus\", \"job\": \"leader\"}",
        .headers = {
            "Content-Type: application/json",
            "Foo: Bar"
        },
    };

    reqst_response* res = request(&opts);

    if (res == NULL) {
        printf("Error occurred when handling request: NULL result\n");
        return 1;
    }

    for (int i = 0; i < res->headers_num; i++) {
        printf("Header %d: %s:%s\n", i+1, res->headers[i].key->data, res->headers[i].val->data);
    }

    printf("Body: %s\n", res->body->data);
    #endif

    #ifdef GET_USERS
    reqst_opts opts = {
        .http_protocol_version = "1.1",
        .method = "GET",
        .url = "reqres.in",
        .path = "/api/users?page=2",
        .headers = {
            "Content-Type: application/json",
        },
    };

    reqst_response* res = request(&opts);

    if (res == NULL) {
        printf("Error occurred when handling request: NULL result\n");
        return 1;
    }

    for (int i = 0; i < res->headers_num; i++) {
        printf("Header %d: %s:%s\n", i+1, res->headers[i].key->data, res->headers[i].val->data);
    }

    printf("Body: %s\n", res->body->data);
    #endif

    #ifdef GET_GITHUB_GISTS
    char auth_header[256];
    if (argc > 1) {
        snprintf(auth_header, 256, "Authorization: Bearer %s", argv[1]);
    } else {
        printf("Provide token as an argument\n");
        exit(0);
    }

    reqst_opts opts = {
        .http_protocol_version = "1.1",
        .method = "GET",
        .url = "api.github.com",
        .path = "/gists",
        .headers = {
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
            "Accept: application/vnd.github+json",
            "X-GitHub-Api-Version: 2022-11-28",
            auth_header
        },
    };

    reqst_response* res = request(&opts);

    if (res == NULL) {
        printf("Error occurred when handling request: NULL result\n");
        return 1;
    }

    printf("Header count: %d\n", res->headers_num);

    for (int i = 0; i < res->headers_num; i++) {
        printf("Header %d: %s:%s\n", i+1, res->headers[i].key->data, res->headers[i].val->data);
    }

    if (res->body != NULL) {
        printf("Body: %s\n", res->body->data);
        printf("Body len is: %d\n", res->body->len);
    } else {
        printf("Body is null\n");
    }
    #endif
}
