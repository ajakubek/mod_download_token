/* Copyright (c) 2008-2012 Adam Jakubek
 * Released under the MIT license (see attached LICENSE file). 
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_lib.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_strings.h"
#include "apr_time.h"

#if APR_HAVE_TIME_H
#include <time.h>
#endif
#if APR_HAVE_STRINGS_H
#include <strings.h>
#endif

/* special value for default timeout */
#define CONFIG_TIMEOUT_UNSET				(-1)

/* 60 seconds of token time-out by default */
#define DOWNLOAD_TOKEN_DEFAULT_TIMEOUT		(60)

/* max length of hexadecimal representation of token
 * update this when adding new hash functions */
#define DOWNLOAD_TOKEN_MAX_LENGTH           (APR_SHA1_DIGESTSIZE*2)


typedef void (*token_generator_func)(char *str, const char *secret,
                                     const char *path, const char *timestamp);

typedef struct
{
    token_generator_func generate_token;    /* generator function */
    size_t token_length;                    /* length of hexadecimal digest */
} token_generator;

typedef struct
{
    char *secret;
    char *prefix;
    size_t prefix_length;
    int timeout;
    const token_generator* token_generator;
} download_token_perdir_conf;


module AP_MODULE_DECLARE_DATA download_token_module;


/* Generates hexadecimal MD5 token from passed secret, path and timestamp,
 * writing it to str.
 * Note that str must be at least APR_MD5_DIGESTSIZE * 2 */
static void generate_md5_token(char *str, const char *secret,
                               const char *path, const char *timestamp)
{
    static const char digits[] = "0123456789abcdef";
    apr_md5_ctx_t ctx;
    char digest[APR_MD5_DIGESTSIZE];
    int i;

    /* calculate MD5 digest */
    apr_md5_init(&ctx);
    apr_md5_update(&ctx, secret, strlen(secret));
    apr_md5_update(&ctx, path, strlen(path));
    apr_md5_update(&ctx, timestamp, 8);
    apr_md5_final(digest, &ctx);

    /* format MD5 digest as hexadecimal string */
    for (i = 0; i < APR_MD5_DIGESTSIZE; ++i)
    {
        str[i*2] = digits[(digest[i] >> 4) & 0x0f];
        str[i*2+1] = digits[digest[i] & 0x0f];
    }
}

static const token_generator md5_token_generator =
{
    generate_md5_token,
    APR_MD5_DIGESTSIZE * 2
};


/* Generates hexadecimal SHA1 token from passed secret, path and timestamp,
 * writing it to str.
 * Note that str must be at least APR_SHA1_DIGESTSIZE * 2 */
static void generate_sha1_token(char *str, const char *secret,
                                const char *path, const char *timestamp)
{
    static const char digits[] = "0123456789abcdef";
    apr_sha1_ctx_t ctx;
    char digest[APR_SHA1_DIGESTSIZE];
    int i;

    /* calculate SHA1 digest */
    apr_sha1_init(&ctx);
    apr_sha1_update(&ctx, secret, strlen(secret));
    apr_sha1_update(&ctx, path, strlen(path));
    apr_sha1_update(&ctx, timestamp, 8);
    apr_sha1_final(digest, &ctx);

    /* format SHA1 digest as hexadecimal string */
    for (i = 0; i < APR_SHA1_DIGESTSIZE; ++i)
    {
        str[i*2] = digits[(digest[i] >> 4) & 0x0f];
        str[i*2+1] = digits[digest[i] & 0x0f];
    }
}

static const token_generator sha1_token_generator =
{
    generate_sha1_token,
    APR_SHA1_DIGESTSIZE * 2
};

#define DOWNLOAD_TOKEN_DEFAULT_GENERATOR    (&sha1_token_generator)


static void *config_perdir_create(apr_pool_t *p, char *path)
{
    download_token_perdir_conf *c;

    c = (download_token_perdir_conf *)apr_pcalloc(
        p, sizeof(download_token_perdir_conf));

    /* initialize default config */
    c->secret = NULL;
    c->prefix = NULL;
    c->prefix_length = 0;
    c->timeout = CONFIG_TIMEOUT_UNSET;
    c->token_generator = NULL;

    return c;
}

static void *config_perdir_merge(apr_pool_t *p, void *base, void *overrides)
{
    download_token_perdir_conf *c, *b, *o;

    c = (download_token_perdir_conf *)apr_pcalloc(
        p, sizeof(download_token_perdir_conf));
    b = (download_token_perdir_conf *)base;
    o = (download_token_perdir_conf *)overrides;

    /* values which are always overridden */
    c->prefix = o->prefix;
    c->prefix_length = o->prefix_length;

    /* values which may be overriden */
    c->secret = b->secret;
    c->timeout = b->timeout;
    c->token_generator = b->token_generator;

    /* override values if needed */
    if (o->secret != NULL)
        c->secret = o->secret;
    if (o->timeout != CONFIG_TIMEOUT_UNSET)
        c->timeout = o->timeout;
    if (o->token_generator != NULL)
        c->token_generator = o->token_generator;

    return c;
}

/* Checks if string is hex number with length digits */
static int validate_hex_string(const char *str, int length)
{
    int i;

    for (i = 0; i < length; ++i)
    {
        if (!apr_isxdigit(str[i]))
            return 0;
    }

    return 1;
}

/* Parses timestamp string (note that it must be validated beforehand) */
static time_t parse_timestamp(const char *str)
{
    int i;
    time_t ts = 0;

    for (i = 0; i < 8; ++i)
    {
        ts <<= 4;
        if (apr_isdigit(str[i]))
            ts |= str[i] - '0';
        else if (apr_isupper(str[i]))
            ts |= str[i] - 'A' + 10;
        else
            ts |= str[i] - 'a' + 10;
    }

    return ts;
}

static int translate_download_token(request_rec *r)
{
    download_token_perdir_conf *conf;
    const token_generator* generator;
    int timeout;
    const char *token, *timestamp, *path;
    time_t ts, now;
    char digest_str[DOWNLOAD_TOKEN_MAX_LENGTH];

    conf = (download_token_perdir_conf *)ap_get_module_config(
        r->per_dir_config, &download_token_module);

    /* directory configuration must be defined */
    if (conf == NULL)
        return DECLINED;

    /* directory must have secret and prefix defined */
    if (conf->secret == NULL || conf->prefix == NULL)
        return DECLINED;

    /* URI must match your prefix */
    if (strncmp(r->uri, conf->prefix, conf->prefix_length) != 0)
        return DECLINED;

    /* get selected token generator */
    generator = (conf->token_generator != NULL) ?
        conf->token_generator : DOWNLOAD_TOKEN_DEFAULT_GENERATOR;

    /* validate existence of token */
    if (!validate_hex_string(r->uri + conf->prefix_length,
                             generator->token_length))
        return HTTP_UNAUTHORIZED;
    token = r->uri + conf->prefix_length;

    /* validate existence of '/' between token and timestamp */
    if (*(token + generator->token_length) != '/')
        return HTTP_UNAUTHORIZED;

    /* validate existence of timestamp */
    if (!validate_hex_string(token + generator->token_length + 1, 8))
        return HTTP_UNAUTHORIZED;
    timestamp = token + generator->token_length + 1;

    /* the rest of URI is path */
    path = timestamp + 8;

    /* validate if path actually exists */
    if (path[0] != '/')
        return HTTP_UNAUTHORIZED;

    /* validate that timestamp has not timed out */
    timeout = (conf->timeout != CONFIG_TIMEOUT_UNSET) ?
        conf->timeout : DOWNLOAD_TOKEN_DEFAULT_TIMEOUT;
    ts = parse_timestamp(timestamp);
    now = apr_time_sec(apr_time_now());
    if (ts > now || ts + timeout < now)
        return HTTP_REQUEST_TIME_OUT;

    /* generator token with specified generator */
    generator->generate_token(digest_str, conf->secret, path, timestamp);

    /* check if tokens match */
    if (strncmp(digest_str, token, generator->token_length) != 0)
        return HTTP_UNAUTHORIZED;

    /* at this point validation is complete, user provided a correct token,
       we must remove the token and timestamp from the URI */
    memmove(r->uri + conf->prefix_length - 1, path, strlen(path) + 1);
    r->filename = apr_pstrdup(r->pool, r->uri);

    /* pass along modified request to other modules */
    return DECLINED;
}

static void download_token_register_hooks(apr_pool_t *p)
{
    ap_hook_translate_name(translate_download_token, NULL, NULL, APR_HOOK_FIRST);
}

/* Returns the directive containing the current command */
static const char *parent_directive(const cmd_parms *cmd)
{
    if (cmd != NULL && cmd->directive != NULL && cmd->directive->parent != NULL)
        return cmd->directive->parent->directive;
    return NULL;
}

static const char *cmd_downloadtoken(cmd_parms *cmd, void *conf, int flag)
{
    download_token_perdir_conf *c = (download_token_perdir_conf *)conf;
    const char *parent;
    int plen;

    /* only allow token validation in per-directory configuration */
    if (cmd->path == NULL || c == NULL)
        return "DownloadToken: only valid in per-directory config files";

    /* command allowed only in <Location> context */
    parent = parent_directive(cmd);
    if (parent == NULL || strcasecmp(parent, "<Location") != 0)
        return "DownloadToken: allowed only within <Location> directive";

    plen = strlen(cmd->path);
    /* prefix must not be empty */
    if (plen == 0)
        return "DownloadToken: empty Location path not allowed";
    /* prefix must be an absolute path */
    if (cmd->path[0] != '/')
        return "DownloadToken: Location path is not a valid absolute URL";

    if (flag)
    {
        /* if prefix does not end with a '/', append it */
        if (cmd->path[plen-1] != '/')
        {
            c->prefix = (char *)apr_pstrcat(cmd->pool, cmd->path, "/", NULL);
            c->prefix_length = plen + 1;
        }
        else
        {
            c->prefix = (char *)apr_pstrdup(cmd->pool, cmd->path);
            c->prefix_length = plen;
        }
    }
    else
    {
        c->prefix = NULL;
        c->prefix_length = 0;
    }

    return NULL;
}

static const char *cmd_downloadtokensecret(cmd_parms *cmd, void *conf,
                                           const char *arg)
{
    download_token_perdir_conf *c = (download_token_perdir_conf *)conf;

    /* only allow token validation in per-directory configuration */
    if (cmd->path == NULL || c == NULL)
        return "DownloadTokenSecret: only valid in per-directory config files";
    /* secret must not be empty */
    if (arg[0] == '\0')
        return "DownloadTokenSecret: empty secret key not allowed";

    c->secret = (char *)apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const char *cmd_downloadtokentimeout(cmd_parms *cmd, void *conf,
                                            const char *arg)
{
    download_token_perdir_conf *c = (download_token_perdir_conf *)conf;
    char *endp;
    int timeout;

    /* timeout argument must not be empty */
    if (arg[0] == '\0')
        return "DownloadTokenTimeout: empty timeout not allowed";

    /* timeout must be a valid positive integer */
    timeout = strtol(arg, &endp, 10);
    if (*endp != '\0')
        return "DownloadTokenTimeout: argument is not a valid integer";
    if (timeout < 1)
        return "DownloadTokenTimeout: argument must not be smaller than 1 second";

    c->timeout = timeout;

    return NULL;
}

static const char *cmd_downloadtokenhashfunction(cmd_parms *cmd, void *conf,
                                                 const char *arg)
{
    download_token_perdir_conf *c = (download_token_perdir_conf *)conf;

    /* token hash function  argument must not be empty */
    if (arg[0] == '\0')
        return "DownloadTokenHashFunction: empty timeout not allowed";

    if (strcasecmp(arg, "md5") == 0)
        c->token_generator = &md5_token_generator;
    else if (strcasecmp(arg, "sha1") == 0)
        c->token_generator = &sha1_token_generator;
    else
        return "DownloadTokenHashFunction: argument is not a valid hash function name";

    return NULL;
}

static const command_rec command_table[] =
{
    AP_INIT_FLAG("DownloadToken", cmd_downloadtoken, NULL, OR_AUTHCFG,
                 "On or Off to enable or disable (default) the token authentication for current location"),
    AP_INIT_TAKE1("DownloadTokenSecret", cmd_downloadtokensecret, NULL, OR_AUTHCFG,
                  "The secret key to generated tokens"),
    AP_INIT_TAKE1("DownloadTokenTimeout", cmd_downloadtokentimeout, NULL, OR_AUTHCFG,
                  "The lifetime in seconds of generated token (default is 60)"),
    AP_INIT_TAKE1("DownloadTokenHashFunction", cmd_downloadtokenhashfunction, NULL, OR_AUTHCFG,
                  "The hash function used (md5 or sha1, default is sha1)"),
    { NULL }
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA download_token_module = {
    STANDARD20_MODULE_STUFF, 
    config_perdir_create,          /* create per-dir    config structures */
    config_perdir_merge,           /* merge  per-dir    config structures */
    NULL,                          /* create per-server config structures */
    NULL,                          /* merge  per-server config structures */
    command_table,                 /* table of config file commands       */
    download_token_register_hooks  /* register hooks                      */
};

