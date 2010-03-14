#include "wec_ssl.h"
#include <limits.h>

INIT_UTILS

MODULE = WEC::SSL::Digest		PACKAGE = WEC::SSL::DigestContext
PROTOTYPES: ENABLE

void
new(char *class, ...)
  PREINIT:
    I32 i;
    ENGINE *engine;
    const EVP_MD *digest;
    const char *name;
    SV *value, *object;
    STRLEN len;
    wec_digest_context digest_context;
    int rc;
  PPCODE:
    if (items % 2 == 0) croak("Odd number of arguments");
    TAINT_NOT;
    digest = NULL;
    engine = NULL;
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 2) switch(name[0]) {
          case 'd': case 'D':
            if (TRY_DIGEST(digest, name, len, value)) goto OK;
            break;
          case 'e': case 'E':
            if (LOW_EQ(name, len, "engine")) {
                if (engine) croak("Multiple engine arguments");
                engine = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
                goto OK;
            }
            break;
        }
        croak("Unknown option '%"SVf"'", ST(i));
      OK:;
    }
    if (!digest) croak("No digest argument");

    Newx(digest_context, 1, struct wec_digest_context);
    object = sv_newmortal();
    sv_setref_pv(object, class, (void*) digest_context);

    EVP_MD_CTX_init(&digest_context->ctx);
    rc = EVP_DigestInit_ex(&digest_context->ctx, digest, engine);
    if (rc != 1) croak("Error initializing digest object");
    digest_context->finished = 0;

    XPUSHs(object);

void
update(wec_digest_context digest_context, SV *sv_string)
  PREINIT:
    STRLEN len;
    const unsigned char *string;
    int rc;
  PPCODE:
    if (digest_context->finished) croak("Digest object is finished");
    string = SV_BYTES(sv_string, len);
    if (len > UINT_MAX) croak("Input length out of range");
    rc = EVP_DigestUpdate(&digest_context->ctx, string, (unsigned int) len);
    if (rc != 1) croak("Could not encrypt data");

SV *
finish(wec_digest_context digest_context)
  PREINIT:
    unsigned int nr_out;
    int rc;
    unsigned char result[EVP_MAX_MD_SIZE];
  CODE:
    if (digest_context->finished) croak("Digest object is finished");
    rc = EVP_DigestFinal_ex(&digest_context->ctx, result, &nr_out);
    if (rc != 1) croak("Could not finish digest");
    RETVAL = newSVpvn(result, nr_out);
    digest_context->finished = 1;
  OUTPUT:
    RETVAL

int
size(wec_digest_context digest_context)
  CODE:
    RETVAL = EVP_MD_CTX_size(&digest_context->ctx);
  OUTPUT:
    RETVAL

int
block_size(wec_digest_context digest_context)
  CODE:
    RETVAL = EVP_MD_CTX_block_size(&digest_context->ctx);
  OUTPUT:
    RETVAL

int
nid(wec_digest_context digest_context)
  CODE:
    RETVAL = EVP_MD_CTX_type(&digest_context->ctx);
  OUTPUT:
    RETVAL

void
DESTROY(wec_digest_context digest_context)
  PPCODE:
    EVP_MD_CTX_cleanup(&digest_context->ctx);
    Safefree(digest_context);

MODULE = WEC::SSL::Digest		PACKAGE = WEC::SSL::HMAC

void
new(char *class, ...)
  PREINIT:
    I32 i;
    ENGINE *engine;
    const EVP_MD *digest;
    const char *name;
    SV *value, *object, *sv_key;
    const U8 *key;
    STRLEN len, key_len;
    wec_hmac hmac_context;
    /* int rc; */
  PPCODE:
    if (items % 2 == 0) croak("Odd number of arguments");
    digest = NULL;
    engine = NULL;
    sv_key = NULL;
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 2) switch(name[0]) {
          case 'd': case 'D':
            if (TRY_DIGEST(digest, name, len, value)) goto OK;
            break;
          case 'e': case 'E':
            if (LOW_EQ(name, len, "engine")) {
                if (engine) croak("Multiple engine arguments");
                croak("Engines not implemented yet");
                goto OK;
            }
            break;
          case 'k': case 'K':
            if (LOW_EQ(name, len, "key")) {
                if (sv_key) croak("Multiple key arguments");
                sv_key = value;
                goto OK;
            }
            break;
        }
        croak("Unknown option '%"SVf"'", ST(i));
      OK:;
    }
    if (!digest) croak("No digest argument");
    if (!sv_key) croak("No key argument");

    key = SV_BYTES(sv_key, key_len);
    if (key_len > INT_MAX) croak("key length out of range");

    Newx(hmac_context, 1, struct wec_hmac);
    object = sv_newmortal();
    sv_setref_pv(object, class, (void*) hmac_context);

    HMAC_CTX_init(&hmac_context->ctx);
    /*rc = */ HMAC_Init_ex(&hmac_context->ctx, key, (int) key_len, digest, engine);
    /* if (rc != 1) croak("Error initializing HMAC object"); */
    hmac_context->finished = 0;

    XPUSHs(object);

void
update(wec_hmac hmac_context, SV *sv_string)
  PREINIT:
    STRLEN len;
    const unsigned char *string;
  PPCODE:
    if (hmac_context->finished) croak("HMAC object is finished");
    string = SV_BYTES(sv_string, len);
    if (len > INT_MAX) croak("Input length out of range");
    HMAC_Update(&hmac_context->ctx, string, (int) len);

SV *
finish(wec_hmac hmac_context)
  PREINIT:
    unsigned int nr_out;
    unsigned char result[EVP_MAX_MD_SIZE];
  CODE:
    if (hmac_context->finished) croak("HMAC object is finished");
    HMAC_Final(&hmac_context->ctx, result, &nr_out);
    RETVAL = newSVpvn(result, nr_out);
    hmac_context->finished = 1;
  OUTPUT:
    RETVAL

void
DESTROY(wec_hmac hmac_context)
  PPCODE:
    HMAC_CTX_cleanup(&hmac_context->ctx);
    Safefree(hmac_context);

BOOT:
    init_utils();
