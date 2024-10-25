# Reqst

Library is work in progress.

## How to use in a project
1. Include header file in your code base.
2. Include `#define REQST_IMPLEMENTATION` in your code.
3. Use it!

Depends on OpenSSL headers and libraries for compiling.

## Examples
### GET request

```
reqst_opts opts = { 
    .http_protocol_version = "1.1",
    .method = "GET",
    .url = "reqres.in",
    .path = "/api/users/2"
};

reqst_response* res = request(&opts);

if (res == NULL) {
    printf("Library error: could not handle request.\n");
    return 1;
}

// res->http_status_code
// res->headers
// res->body
```