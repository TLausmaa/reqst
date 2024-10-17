#pragma once

typedef struct response {
    char* data;
    int len;
} response;

void request(char* method, char* url);
