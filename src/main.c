#define SERV_REQ_IMPLEMENTATION
#include "req.h"

int main()
{
    req_opts opts = { 
        .http_protocol_version = "2",
        .method = "GET",
        .url = "yle.fi" 
    };

    serv_response* res = request(&opts);

    if (res == NULL) {
        printf("Error occurred when handling request: NULL result\n");
        return 1;
    } 

    printf("HTTP status code was: %d\n", res->http_status_code);
}
