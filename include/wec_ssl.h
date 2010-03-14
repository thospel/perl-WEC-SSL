#define PERL_NO_GET_CONTEXT	/* we want efficiency */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#define UTILS_API_VERSION "0.1"
#define PACKAGE_BASE "WEC::SSL"

#define DO_MAGIC	1	/* Support magic */
#define SENSITIVE	1

#define SERVER		1
#define CLIENT		2

#define DEFAULT_CIPHERS "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"

/* Just some number we made up */
#define MAX_VERIFY_DEPTH	65535

#define MORTALCOPY(sv) sv_2mortal(newSVsv(sv))

#define TAINT_RAND (PL_tainted = RAND_status() == 1 ? FALSE : TRUE)

#define REF_TAINTED(arg, tainted, class, context)	\
	PUSHs(utils->ref_tainted(aTHX_ arg, tainted, class, context))

typedef struct wec_bio {
    BIO *bio;
    struct wec_bio_chain *chain;
    struct wec_ssl *ssl;
} *wec_bio, *wec_bio_file, *wec_bio_b64, *wec_bio_memory,
  *wec_bio_cipher, *wec_bio_encrypt, *wec_bio_decrypt, *wec_bio_buffer;

typedef struct wec_bio_pair {
    /* Layout MUST start like that of wec_bio */
    BIO *bio;
    struct wec_bio_chain *chain;
    struct wec_ssl *ssl;
    struct wec_bio_pair *peer;
} *wec_bio_pair;

typedef struct wec_bio_socket {
    /* Layout MUST start like that of wec_bio */
    BIO *bio;
    struct wec_bio_chain *chain;
    struct wec_ssl *ssl;
    IO *socket;
} *wec_bio_socket;

typedef struct wec_bio_chain {
    UV nr_bio, nr_allocated;
    SV **bio;
    struct wec_ssl *ssl;
} *wec_bio_chain;

typedef struct wec_ssl_context {
    SSL_CTX *ctx;

    /* error information */
    SV *error_cert;
    int error_depth;
    int error_code;
} *wec_ssl_context;

typedef struct wec_ssl {
    SSL *ssl;
    SV *bio_read, *bio_write, *context;
    int mode;
} *wec_ssl;

typedef struct wec_x509 {
    X509 *x509;
} *wec_x509;

typedef struct wec_cipher_context {
    EVP_CIPHER_CTX ctx;
    bool finished;
} *wec_cipher_context, *wec_encrypt, *wec_decrypt;

typedef struct wec_digest_context {
    EVP_MD_CTX ctx;
    bool finished;
} *wec_digest_context;

typedef struct wec_hmac {
    HMAC_CTX ctx;
    bool finished;
} *wec_hmac;

#define ENGINE_NEEDS_FREE	1
#define ENGINE_NEEDS_FINISH	2
typedef struct wec_engine {
    ENGINE *e;
    bool flags;
} *wec_engine;

typedef struct wec_bigint {
    BIGNUM num;
#if SENSITIVE
    bool sensitive;
#endif /* SENSITIVE */
} *wec_bigint;

typedef struct wec_reciprocal {
    BN_RECP_CTX ctx;
#if SENSITIVE
    bool sensitive;
#endif /* SENSITIVE */
} *wec_reciprocal;

typedef struct wec_montgomery {
    BN_MONT_CTX ctx;
#if SENSITIVE
    bool sensitive;
#endif /* SENSITIVE */
} *wec_montgomery;

extern bool wec_ssl_ciphers_loaded;

struct util {
    const char *api_version;
    int	engine_refcount_offset;
    void (*not_a_number)(pTHX_ SV *sv, const char *from, STRLEN len);
    SV *(*c_sv)(pTHX_ SV *object, const char *class,const char *context);
    void *(*c_object)(pTHX_ SV *object, const char *class,const char *context);
    int (*get_int)(pTHX_ SV *value, 
#if SENSITIVE
                   bool *sensitive, 
#endif /* SENSITIVE */
                   const char *context);
    long (*get_long)(pTHX_ SV *value, const char *context);
    UV (*get_UV)(pTHX_ SV *value, const char *context);
    int (*low_eq)(const char *name, const char *target);
    const U8 *(*sv_bytes)(pTHX_ SV *sv, STRLEN *l);
    const U8 *(*sv_canonical)(pTHX_ SV *sv, STRLEN *l);
    const char *(*sv_file)(pTHX_ SV *sv);
    STRLEN (*utf8_copy)(pTHX_ U8 *to,   STRLEN to_len,
                        const U8 *from, STRLEN from_len);
    wec_bio (*sv_to_bio)(pTHX_ SV **sv_bio, const char *parameter_name);
    const char *(*c_ascii)(pTHX_ SV *sv_string, const char *context);
    SV *(*ref_tainted)(pTHX_ SV *arg, SV *tainted,
                       const char *class, const char *context);
    void (*load_engines)(void);
    int (*discover_engine_refcount_offset)(void);
    const EVP_CIPHER *(*cipher_by_name)(pTHX_ SV *name);
    const EVP_MD *(*digest_by_name)(pTHX_ SV *name);
    ENGINE *(*engine_by_name)(pTHX_ SV *name);
    int (*try_cipher)(pTHX_ const char *name, STRLEN len, SV *value, 
                      const EVP_CIPHER **cipher);
    int (*try_digest)(pTHX_ const char *name, STRLEN len, SV *value, 
                      const EVP_MD **digest);
    int (*try_engine)(pTHX_ const char *name, STRLEN len, SV *value, 
                      const ENGINE **engine);
    void (*crypto_croak)(const char *fallback, ...) __attribute__((noreturn));
};

#define C_SV(object, class, context) utils->c_sv(aTHX_ object, class, context)

#define TRY_C_OBJECT(object, class)	\
	utils->c_object(aTHX_ object, class, NULL)
#define C_OBJECT(object, class, context)	\
	utils->c_object(aTHX_ object, class, context)

#if SENSITIVE
# define GET_INT_SENSITIVE(value, sensitive, context)	\
	utils->get_int(aTHX_ value, &sensitive, context)
# define GET_INT(value, context)			\
	utils->get_int(aTHX_ value, NULL, context)
#else /* SENSITIVE */
# define GET_INT_SENSITIVE(value, sensitive, context)	\
	utils->get_int(aTHX_ value, context)
# define GET_INT(value, context)	utils->get_int(aTHX_ value, context)
#endif /* SENSITIVE */

#define GET_LONG(value, context) utils->get_long(aTHX_ value, context)

#define GET_UV(value, context) utils->get_UV(aTHX_ value, context)

#define NOT_A_NUMBER(sv, from, len) utils->not_a_number(aTHX_ sv, from, len)

#define SV_BYTES(sv, len) utils->sv_bytes(aTHX_ sv, &(len))

#define SV_CANONICAL(sv, len) utils->sv_canonical(aTHX_ sv, &(len))

#define SV_FILE(sv) utils->sv_file(aTHX_ sv)

#define UTF8_COPY(to, to_len, from, from_len)	\
	utils->utf8_copy(aTHX_ to, to_len, from, from_len)

#define LOW_EQ(name, len, string)	\
    ((len) == sizeof(string "")-1 && utils->low_eq(name, string))

#define SV_TO_BIO(bio, param_name) utils->sv_to_bio(aTHX_ &(bio), param_name)

#define C_CLASS(string) ((const char *) utils->c_ascii(aTHX_ string, "class"))
#define C_ASCII(string, context) utils->c_ascii(aTHX_ string, context)

#define LOAD_ENGINES()	utils->load_engines()
#define ENGINE_STRUCTURE_REFCOUNT(e)	((int *) e)[utils->engine_refcount_offset < 0 ? utils->discover_engine_refcount_offset() : utils->engine_refcount_offset]
#define ENGINE_FUNCTION_REFCOUNT(e)	((int *) e)[1+(utils->engine_refcount_offset < 0 ? utils->discover_engine_refcount_offset() : utils->engine_refcount_offset)]

#define DIGEST_BY_NAME(name) utils->digest_by_name(aTHX_ name)
#define CIPHER_BY_NAME(name) utils->cipher_by_name(aTHX_ name)
#define ENGINE_BY_NAME(name) utils->engine_by_name(aTHX_ name)

#define TRY_CIPHER(cipher, name, len, value)	\
	 utils->try_cipher(aTHX_ name, len, value, &(cipher))
#define TRY_DIGEST(digest, name, len, value)	\
	 utils->try_digest(aTHX_ name, len, value, &(digest))
#define TRY_ENGINE(engine, name, len, value)	\
	 utils->try_engine(aTHX_ name, len, value, &(engine))

#define CRYPTO_CROAK utils->crypto_croak

#define INIT_UTILS							\
struct util *utils;							\
void init_utils(void) {							\
    SV *class, *result;							\
    I32 count;								\
    IV tmp;								\
    struct util *u;							\
    dTHX;								\
    dSP;								\
									\
    class = sv_newmortal();						\
    sv_setpv(class, PACKAGE_BASE "::Utils");				\
									\
    PUSHMARK(SP);							\
    XPUSHs(class);							\
    PUTBACK;								\
    count = call_method("context", G_SCALAR);				\
    if (count != 1) croak("Expected 1 result from context");		\
    SPAGAIN;								\
    result = POPs;							\
    PUTBACK;								\
    if (!SvOK(result)) croak("context result is undefined");		\
    if (!sv_derived_from(result, PACKAGE_BASE "::Utils"))		\
        croak("context result is not derived from " PACKAGE_BASE "::Utils");	\
    result = SvRV(result);						\
    if (!result) croak("context result refers to nothing");		\
    tmp = SvIV(result);							\
    if (!tmp) croak("context result refers to NULL pointer");		\
    u = INT2PTR(struct util *, tmp);					\
    if (strcmp(u->api_version, UTILS_API_VERSION))			\
        croak("Utils provided API %s, but I expected %s",		\
              u->api_version, UTILS_API_VERSION);			\
    utils = u;								\
}
