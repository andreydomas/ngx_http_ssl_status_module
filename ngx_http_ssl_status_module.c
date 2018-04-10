#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_ssl_status_handler(ngx_http_request_t *r);
static char *ngx_http_ssl_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_ssl_status_module_commands[] = {

    { ngx_string("ssl_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_ssl_status,
      0,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_ssl_status_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,        /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_status_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_status_module_ctx,       /* module context */
    ngx_http_ssl_status_module_commands,   /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_ssl_status_handler(ngx_http_request_t *r) {
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    size = sizeof("number:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("connect:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("connect_good:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("connect_renegotiate:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("accept:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("accept_good:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("accept_renegotiate:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("hits:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("cb_hits:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("misses:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("timeouts:  \n") + NGX_ATOMIC_T_LEN
         + sizeof("cache_full:  \n") + NGX_ATOMIC_T_LEN;


    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ngx_http_ssl_srv_conf_t *sscf;
    sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);

    b->last = ngx_sprintf(b->last, "number: %uA \n", SSL_CTX_sess_number(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "connect: %uA \n", SSL_CTX_sess_connect(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "connect_good: %uA \n", SSL_CTX_sess_connect_good(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "connect_renegotiate: %uA \n", SSL_CTX_sess_connect_renegotiate(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "accept: %uA \n", SSL_CTX_sess_accept(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "accept_good: %uA \n", SSL_CTX_sess_accept_good(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "accept_renegotiate: %uA \n", SSL_CTX_sess_accept_renegotiate(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "hits: %uA \n", SSL_CTX_sess_hits(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "cb_hits: %uA \n", SSL_CTX_sess_cb_hits(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "misses: %uA \n", SSL_CTX_sess_misses(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "timeouts: %uA \n", SSL_CTX_sess_timeouts(sscf->ssl.ctx));
    b->last = ngx_sprintf(b->last, "cache_full: %uA \n", SSL_CTX_sess_cache_full(sscf->ssl.ctx));

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_ssl_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sslcf;
    ngx_http_core_loc_conf_t  *clcf;

    sslcf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

    if (!sslcf->enable) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
             "ssl_status present but SSL is not configured");
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ssl_status_handler;

    return NGX_CONF_OK;
}

