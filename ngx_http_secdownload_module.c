/*
 * Copyright (C) TrungTM
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


typedef struct {
    ngx_str_t   secret;
    ngx_str_t   prefix;
    ngx_uint_t  timeout;
} ngx_http_secdownload_conf_t;


static void *ngx_http_secdownload_create_conf(ngx_conf_t *cf);
static char *ngx_http_secdownload_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_secdownload_add_variables(ngx_conf_t *cf);


static ngx_command_t  ngx_http_secdownload_commands[] = {
    {
        ngx_string("secdownload.secret"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_secdownload_conf_t, secret),
        NULL
    },

    {
        ngx_string("secdownload.uri-prefix"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_secdownload_conf_t, prefix),
        NULL
    },

    {
        ngx_string("secdownload.timeout"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_secdownload_conf_t, timeout),
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_secdownload_module_ctx = {
    ngx_http_secdownload_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    ngx_http_secdownload_create_conf,      /* create location configuration */
    ngx_http_secdownload_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_secdownload_module = {
    NGX_MODULE_V1,
    &ngx_http_secdownload_module_ctx,      /* module context */
    ngx_http_secdownload_commands,         /* module directives */
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


static ngx_str_t  ngx_http_secdownload = ngx_string("secdownload_uri");


static ngx_int_t
is_hex_len(const u_char *str, size_t len)
{
    size_t i;

    if (NULL == str) return 0;

    for (i = 0; i < len && *str; i++, str++) {
        /* illegal characters */
        if (!((*str >= '0' && *str <= '9') ||
                (*str >= 'a' && *str <= 'f') ||
                (*str >= 'A' && *str <= 'F'))
           ) {
            return 0;
        }
    }

    return i == len;
}

/*
static void
log_hash(ngx_http_request_t *r, u_char hash[16])
{
    char buffer[33];
    ngx_int_t i;

    for (i = 0; i < 16; i++) {
        sprintf(&buffer[i * 2], "%02x", hash[i]);
    }

    buffer[32] = '\0';

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Correct md5: %s", buffer);
}
*/

static ngx_int_t
ngx_http_secdownload_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                         *md5_str, *rel_uri, *ts_str;
    time_t                         ts, cur_ts;
    size_t                         len;
    ngx_int_t                      n;
    ngx_uint_t                     i;
    ngx_md5_t                      md5;
    ngx_http_secdownload_conf_t    *conf;
    u_char                         hash[16];

    conf = ngx_http_get_module_loc_conf(r, ngx_http_secdownload_module);

    if (conf->secret.len == 0) {
        v->not_found = 1;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "secdownload: secret.len = 0");

        return NGX_OK;
    }

    if ( 0 != ngx_strncasecmp(r->uri.data, conf->prefix.data, conf->prefix.len) ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "secdownload: uri-prefix does not match");
    	return NGX_OK;
    }

    md5_str = &r->uri.data[1] + conf->prefix.len - 1;

    if (!is_hex_len(md5_str, 32)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "secdownload: md5_str: expected 32 chars");
        v->not_found = 1;

        return NGX_OK;
    }

    if (*(md5_str + 32) != '/') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "secdownload: md5_str: / not found");
        v->not_found = 1;

        return NGX_OK;
    }

    ts_str = md5_str + 32 + 1;

    if (!is_hex_len(ts_str, 8)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "secdownload: ts_str: expected 8 chars");
        v->not_found = 1;

        return NGX_OK;
    }

    if (*(ts_str + 8) != '/') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "secdownload: ts_str: / not found");
        v->not_found = 1;

        return NGX_OK;
    }

    ts = ngx_hextoi(ts_str, 8);
    cur_ts = ngx_time();

    /* timed-out */
    if ( (cur_ts > ts && (unsigned int) (cur_ts - ts) > conf->timeout) ||
            (cur_ts < ts && (unsigned int) (ts - cur_ts) > conf->timeout) ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "secdownload: timed out");
        v->not_found = 1;

        return NGX_OK;
    }

    rel_uri = ts_str + 8;
    len = r->uri.data + r->uri.len - rel_uri;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, conf->secret.data, conf->secret.len);
    ngx_md5_update(&md5, rel_uri, len);
    ngx_md5_update(&md5, ts_str, 8);
    ngx_md5_final(hash, &md5);
    
    for (i = 0; i < 4; i++) {
        n = ngx_hextoi(&md5_str[2 * i], 2);
        if (n == NGX_ERROR || n != hash[i]) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "secdownload: md5 did not match");
            /* debug only */
            /* log_hash(r, hash); */

            v->not_found = 1;

            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "secdownload: Everything is OK!");

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = rel_uri;

    return NGX_OK;
}


static void *
ngx_http_secdownload_create_conf(ngx_conf_t *cf)
{
    ngx_http_secdownload_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secdownload_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->timeout = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_secdownload_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secdownload_conf_t *prev = parent;
    ngx_http_secdownload_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->secret, prev->secret, "");
    ngx_conf_merge_uint_value(conf->timeout, prev->timeout, 3600);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_secdownload_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_secdownload, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_secdownload_variable;

    return NGX_OK;
}
