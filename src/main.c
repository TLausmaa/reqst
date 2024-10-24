#include <stdio.h>
#define REQST_IMPLEMENTATION
#include "req.h"

//#define GET
//#define POST
#define GET_USERS

int main()
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
}
