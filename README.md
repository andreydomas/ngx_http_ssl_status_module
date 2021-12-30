
ngx_http_ssl_status_module
==========================

Nginx SSL statistics module.

Each worker process appends its SSL statistics values to shared memory zone 
from which this values can be viewed by HTTP-request.
It's possible to collect independent statistics for a virtual server or assign 
multiple virtual servers to one zone and get summed up values for them.


Building
--------
The module can be build only as built-in module, not dynamic.
Add --add-module=<path_to_this_cloned_repo> to nginx configure script. Example:
```bash
cd nginx-src
./configure --with-http_ssl_module --add-module=../ngx_http_ssl_status_module
make
```

Usage
-----
A server saves its SSL statistics to a zone defined by ssl_status_zone 
(default: "default") option.
Statistics can be accessed by a location marked by ssl_status option.
Example:
```nginx
server {
    server_name A;
    ...
    ssl_status_zone zone1;
}

server {
    server_name B;
    ...
    ssl_status_zone zone1;
}

server {
    server_name C;
    ...
    ssl_status_zone zone2;

    location /stat1 {
        ssl_status zone1;
    }

    location /stat2 {
        ssl_status zone2;
    }
}
```
* Statistics for servers A and B (with summed up counters) will be available at 
/stat1 of server C.
* Statistics for server C will be available at /stat2 of server C.

Each field name corresponds apropriate statistics function name: 
[SSL_CTX_sess_*](https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_sess_connect.html)
```
curl https://localhost/ssl_stat
number: 0
connect: 0
connect_good: 0
connect_renegotiate: 0
accept: 21
accept_good: 21
accept_renegotiate: 0
hits: 5
cb_hits: 0
misses: 0
timeouts: 0
cache_full: 0
```
