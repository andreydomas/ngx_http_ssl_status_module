
ngx_http_ssl_status_module
==========================

Nginx SSL statistics module.


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
Add _ssl_status_ option to the location.
```nginx
location /ssl_stat {
        ssl_status;
}
```

Each field name corresponds apropriate statistics function name: [SSL_CTX_sess_*](https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_sess_connect.html)
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
