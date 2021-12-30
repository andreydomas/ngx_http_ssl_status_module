/* @source ngx_http_ssl_status_module
 * Nginx SSL statistics module.
 * @author: Andrey Domas (andrey.domas@gmail.com)
 * @@
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define SHM_SIZE 65536
#define SHM_DEFAULT_NAME "default"


typedef struct {
    ngx_uint_t number;
    ngx_uint_t connect;
    ngx_uint_t connect_good;
    ngx_uint_t connect_renegotiate;
    ngx_uint_t accept;
    ngx_uint_t accept_good;
    ngx_uint_t accept_renegotiate;
    ngx_uint_t hits;
    ngx_uint_t cb_hits;
    ngx_uint_t misses;
    ngx_uint_t timeouts;
    ngx_uint_t cache_full;
} ngx_http_ssl_status_counters_t;


typedef struct {
    ngx_shm_zone_t *shm_zone;
} ngx_http_ssl_status_loc_conf_t;


typedef struct {
    ngx_shm_zone_t *shm_zone;
    ngx_http_ssl_status_counters_t *prev_counters;
} ngx_http_ssl_status_srv_conf_t;


static void *ngx_http_ssl_status_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_ssl_status_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_ssl_status_module_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_ssl_status_handler(ngx_http_request_t *r);
static char *ngx_http_ssl_status(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_ssl_status_zone(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);


/* Timer event for periodic stat polling */
static ngx_event_t ngx_http_ssl_status_timer;
// milliseconds
#define STAT_POLL_INTERVAL 1000


static ngx_command_t  ngx_http_ssl_status_module_commands[] = {

    { ngx_string("ssl_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ssl_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssl_status_loc_conf_t, shm_zone),
      NULL },

    { ngx_string("ssl_status_zone"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_ssl_status_zone,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_status_srv_conf_t, shm_zone),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_status_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ssl_status_create_srv_conf,   /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ssl_status_create_loc_conf,   /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_status_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_status_module_ctx,         /* module context */
    ngx_http_ssl_status_module_commands,     /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    ngx_http_ssl_status_module_init_worker,  /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


/* Reply on location marked with ssl_status */
static ngx_int_t ngx_http_ssl_status_handler(ngx_http_request_t *r) {
    size_t             size;
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_http_ssl_status_loc_conf_t  *ssllcf;
    ngx_http_ssl_status_counters_t  *counters;

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

    // get location configuration struct to access its shm zone
    ssllcf = ngx_http_get_module_loc_conf(r, ngx_http_ssl_status_module);
    counters = ssllcf->shm_zone->data;

    b->last = ngx_sprintf(b->last, "number: %uA \n",
            counters->number);

    b->last = ngx_sprintf(b->last, "connect: %uA \n",
            counters->connect);

    b->last = ngx_sprintf(b->last, "connect_good: %uA \n",
            counters->connect_good);

    b->last = ngx_sprintf(b->last, "connect_renegotiate: %uA \n",
            counters->connect_renegotiate);

    b->last = ngx_sprintf(b->last, "accept: %uA \n",
            counters->accept);

    b->last = ngx_sprintf(b->last, "accept_good: %uA \n",
            counters->accept_good);

    b->last = ngx_sprintf(b->last, "accept_renegotiate: %uA \n",
            counters->accept_renegotiate);

    b->last = ngx_sprintf(b->last, "hits: %uA \n",
            counters->hits);

    b->last = ngx_sprintf(b->last, "cb_hits: %uA \n",
            counters->cb_hits);

    b->last = ngx_sprintf(b->last, "misses: %uA \n",
            counters->misses);

    b->last = ngx_sprintf(b->last, "timeouts: %uA \n",
            counters->timeouts);

    b->last = ngx_sprintf(b->last, "cache_full: %uA \n",
            counters->cache_full);

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


static ngx_int_t
ngx_http_ssl_status_init_zone(ngx_shm_zone_t *shm_zone, void *data) {
    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    shm_zone->data = ngx_slab_calloc(shpool,
            sizeof(ngx_http_ssl_status_counters_t));

    if (shm_zone->data == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_shm_zone_t* get_or_create_shm_zone(ngx_conf_t *cf, ngx_str_t *name) {
    ngx_shm_zone_t* zone = ngx_shared_memory_add(cf, name, SHM_SIZE,
                                                 &ngx_http_ssl_status_module);
    if (zone == NULL) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,
                "error accessing shm-zone \"%s\"", name->data);
        return NULL;
    }
    zone->init = ngx_http_ssl_status_init_zone;
    return zone;
}


/* Location configuration, ssl_status directive */
static char *
ngx_http_ssl_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t        *clcf;
    ngx_http_ssl_status_loc_conf_t  *ssllcf = conf;
    ngx_str_t                       *value = cf->args->elts;

    ssllcf->shm_zone = get_or_create_shm_zone(cf, &value[1]);

    if (ssllcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    // attach handler to generate reply on this location
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ssl_status_handler;

    return NGX_CONF_OK;
}


// add only delta (current - previous) to counter in shm
// remember last (current) value for feature calls
#define ngx_http_ssl_status_add_counter_delta(counter, openssl_func) \
    tmp = openssl_func(sscf->ssl.ctx); \
    counters->counter += tmp - sslscf->prev_counters->counter; \
    sslscf->prev_counters->counter = tmp;


/* This will be called by timer to append openssl stat values of current worker
 * process to counters in shm */
static void ngx_http_ssl_status_poll_stat(ngx_event_t *ev) {
    ngx_uint_t                       s, tmp;
    ngx_http_core_main_conf_t       *cmcf = ev->data;
    ngx_http_ssl_srv_conf_t         *sscf;
    ngx_http_core_srv_conf_t       **cscfp;
    ngx_http_ssl_status_srv_conf_t  *sslscf;
    ngx_http_ssl_status_counters_t  *counters;

    // get all servers in current worker
    cscfp = cmcf->servers.elts;

    // for server_index in servers
    for (s = 0; s < cmcf->servers.nelts; s++) {
        //ssl module config
        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        // this module config
        sslscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_status_module.ctx_index];
        // if ssl_status_zone is defined && ssl is enabled
        if (sslscf->shm_zone != NULL && sscf->ssl.ctx != NULL) {
            counters = sslscf->shm_zone->data;

            ngx_http_ssl_status_add_counter_delta(
                    number, SSL_CTX_sess_number);

            ngx_http_ssl_status_add_counter_delta(
                    connect, SSL_CTX_sess_connect);

            ngx_http_ssl_status_add_counter_delta(
                    connect_good, SSL_CTX_sess_connect_good);

            ngx_http_ssl_status_add_counter_delta(
                    connect_renegotiate, SSL_CTX_sess_connect_renegotiate);

            ngx_http_ssl_status_add_counter_delta(
                    accept, SSL_CTX_sess_accept);

            ngx_http_ssl_status_add_counter_delta(
                    accept_good, SSL_CTX_sess_accept_good);

            ngx_http_ssl_status_add_counter_delta(
                    accept_renegotiate, SSL_CTX_sess_accept_renegotiate);

            ngx_http_ssl_status_add_counter_delta(
                    hits, SSL_CTX_sess_hits);

            ngx_http_ssl_status_add_counter_delta(
                    cb_hits, SSL_CTX_sess_cb_hits);

            ngx_http_ssl_status_add_counter_delta(
                    misses, SSL_CTX_sess_misses);

            ngx_http_ssl_status_add_counter_delta(
                    timeouts, SSL_CTX_sess_timeouts);

            ngx_http_ssl_status_add_counter_delta(
                    cache_full, SSL_CTX_sess_cache_full);
        }
    }

    ngx_add_timer(ev, STAT_POLL_INTERVAL);
}


/* Server configuration, ssl_status_zone directive */
static char *
ngx_http_ssl_status_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_ssl_status_srv_conf_t  *sslscf = conf;
    ngx_str_t                       *value = cf->args->elts;

    sslscf->shm_zone = get_or_create_shm_zone(cf, &value[1]);
    if (sslscf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static void *ngx_http_ssl_status_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_ssl_status_srv_conf_t *conf;
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_ssl_status_srv_conf_t));
    conf->prev_counters = ngx_pcalloc(cf->pool,
            sizeof(ngx_http_ssl_status_counters_t));
    ngx_str_t default_zone_name = ngx_string(SHM_DEFAULT_NAME);
    conf->shm_zone = get_or_create_shm_zone(cf, &default_zone_name);
    if (conf->shm_zone == NULL)
        return NULL;
    return conf;
}


static void *ngx_http_ssl_status_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_ssl_status_loc_conf_t *conf;
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_ssl_status_loc_conf_t));
    return conf;
}


/* When a worker has started: run periodic task to poll openssl stats */
static ngx_int_t ngx_http_ssl_status_module_init_worker(ngx_cycle_t *cycle) {
    ngx_http_core_main_conf_t  *cmcf = ngx_http_cycle_get_module_main_conf(
            cycle, ngx_http_core_module);

    ngx_http_ssl_status_timer.handler = ngx_http_ssl_status_poll_stat;
    ngx_http_ssl_status_timer.log = cycle->log;
    // attach ngx_http_core_main_conf_t struct to access all configured servers
    ngx_http_ssl_status_timer.data = cmcf;
    // allows workers shutting down gracefully
    ngx_http_ssl_status_timer.cancelable = 1;
    ngx_add_timer(&ngx_http_ssl_status_timer, STAT_POLL_INTERVAL);
    return NGX_OK;
}
