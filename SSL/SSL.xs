#include "wec_ssl.h"

INIT_UTILS

static int dummy_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d,
                     int idx, long argl, void *argp) __attribute__((noreturn));
static int dummy_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d,
                     int idx, long argl, void *argp) {
    croak("Dupping not expected. Please report how you triggered this");
}

static int ssl_wrapper_index = -1;
static void boot(pTHX) {
    /* Failure is actually impossible according to the documentation */
    if (SSL_library_init() != 1)
        croak("Could not initialize SSL library");
    if (ssl_wrapper_index < 0) {
        int index = SSL_get_ex_new_index(0, "perl_wrapper",
                                         NULL, dummy_dup, NULL);
        if (index < 0)
            croak("Could not allocate a new application data index");
        ssl_wrapper_index = index;
    }
}

static int ssl_write(pTHX_ SSL *ssl, SV *bufsv) {
    STRLEN len, temp_len;
    const U8 *string, *str_end, *from;
    U8 *temp, *to;
    int rc;
    UV ch;

    string = SvPV(bufsv, len);
    if (SvUTF8(bufsv)) {
        str_end = string + len;
        for (from = string; from < str_end; from++) {
            if (!UNI_IS_INVARIANT(*from)) {
                /* We have real UTF8 */
                U32 utf8_flags  = ckWARN(WARN_UTF8) ? 0 : UTF8_ALLOW_ANY;
                temp_len = from - string;
                New(__LINE__ % 1000, temp, len, U8);
                Copy(string, temp, temp_len, U8);
                to = temp+temp_len;
                for (; from < str_end; from += temp_len) {
                    ch = utf8n_to_uvchr((U8*) from, str_end-from, &temp_len,
                                        utf8_flags);
                    if (temp_len == (STRLEN) -1 || temp_len == 0) {
                        Safefree(temp);
                        croak("Malformed UTF-8 string in write");
                    }
                    if (ch >= 0x100) {
                        Safefree(temp);
                        croak("UTF-8 string can't be downgraded");
                    }
                    *to++ = ch;
                }
                rc = SSL_write(ssl, (char *) temp, to-temp);
                Safefree(temp);
                return rc;
            }
        }
        /* Nothing in the string is actually encoded */
    }
    rc = SSL_write(ssl, string, len);
    return rc;
}

static const char *ssl_strerror(int rc) {
    switch(rc) {
      case 0: return "SSL_ERROR_NONE";
      case 1: return "SSL_ERROR_SSL";
      case 2: return "SSL_ERROR_WANT_READ";
      case 3: return "SSL_ERROR_WANT_WRITE";
      case 4: return "SSL_ERROR_WANT_X509_LOOKUP";
      case 5:
        /* look at error stack/return value/errno */
        return "SSL_ERROR_SYSCALL";
      case 6: return "SSL_ERROR_ZERO_RETURN";
      case 7: return "SSL_ERROR_WANT_CONNECT";
      case 8: return "SSL_ERROR_WANT_ACCEPT";
      default: return "Unknown error";
    }
}

static void ssl_croak(wec_ssl ssl, const char *operation, int rc) __attribute__((noreturn));
static void ssl_croak(wec_ssl ssl, const char *operation, int rc) {
    int ssl_rc;

    ssl_rc = SSL_get_error(ssl->ssl, rc);
    croak("Could not %s (%s)", operation, ssl_strerror(ssl_rc));
}

static int verify_callback(int ok, X509_STORE_CTX *store) {
    if (!ok) {
        dTHX;
        SSL  *ssl;
        wec_ssl ssl_wrapper;
        wec_ssl_context ssl_context;
        X509 *error_cert;
        wec_x509 x509;
        SV *sv_x509;
        IV tmp;
        /*
         * Retrieve the pointer to the SSL of the connection currently treated
         * and the application specific data stored into the SSL object.
         */
        int ssl_index = SSL_get_ex_data_X509_STORE_CTX_idx();
        /* croaking out of a callback is probably a BAD idea */
        if (ssl_index < 0) croak("Assert: could not determine SSL_get_ex_data_X509_STORE_CTX_idx");
        ssl = X509_STORE_CTX_get_ex_data(store, ssl_index);
        if (!ssl) croak("Assert: could not determine SSL object in verify_callback");
        ssl_wrapper = SSL_get_ex_data(ssl, ssl_wrapper_index);
        if (!ssl_wrapper) croak("Assert: could not determine perl SSL object in verify_callback");
        if (!ssl_wrapper->context) croak("Assert: No context in SSL object");
        tmp = SvIV(ssl_wrapper->context);
        if (!tmp) croak("SSL object context is not really a " PACKAGE_BASE "::Context object");
        ssl_context = INT2PTR(wec_ssl_context, tmp);

        New(__LINE__ % 1000, x509, 1, struct wec_x509);
        x509->x509 = NULL;
        sv_x509 = sv_newmortal();
        sv_setref_pv(sv_x509, PACKAGE_BASE "::X509", (void*) x509);
        /* Forget about the temporary RV */
        sv_x509 = SvRV(sv_x509);

        error_cert = X509_STORE_CTX_get_current_cert(store);
        CRYPTO_add(&error_cert->references, 1, CRYPTO_LOCK_X509);
        x509->x509 = error_cert;

        if (ssl_context->error_cert) sv_2mortal(ssl_context->error_cert);
        SvREFCNT_inc(sv_x509);
        ssl_context->error_cert = sv_x509;
        ssl_context->error_depth = X509_STORE_CTX_get_error_depth(store);
        ssl_context->error_code  = X509_STORE_CTX_get_error(store);
    }

    return ok;
}

static SV *ssl_options(pTHX_ SV *sv_ssl_context,
                       SV **args, I32 items, int direction) {
    int i, verify, rc;
    const char *name, *ciphers;
    SV *bio_read, *bio_write, *value, *sv_ssl;
    wec_ssl_context ssl_context;
    wec_ssl ssl;
    BIO *BIO_read, *BIO_write;
    STRLEN len;
    IV verify_depth, tmp;
    wec_bio bio;

    if (items % 2) croak("Odd number of arguments");

    if (!SvOK(sv_ssl_context)) croak("ssl_context is undefined");
    if (!sv_derived_from(sv_ssl_context, PACKAGE_BASE "::Context"))
	croak("ssl_context is not of type " PACKAGE_BASE "::Context");
    if (!SvROK(sv_ssl_context)) croak("ssl_context is not a reference");
    sv_ssl_context = SvRV(sv_ssl_context);
    tmp = SvIV(sv_ssl_context);
    if (!tmp) croak("ssl_context is not really a " PACKAGE_BASE "::Context object");
    ssl_context = INT2PTR(wec_ssl_context, tmp);

    New(__LINE__ % 1000, ssl, 1, struct wec_ssl);
    ssl->context = sv_ssl_context; SvREFCNT_inc(sv_ssl_context);
    ssl->ssl = NULL;
    ssl->mode = 0;
    ssl->bio_read = ssl->bio_write = NULL;
    sv_ssl = sv_newmortal();
    sv_setref_pv(sv_ssl, PACKAGE_BASE "::SSL", (void*) ssl);

    ssl->ssl = SSL_new(ssl_context->ctx);
    if (!ssl->ssl) croak("Error creatring an SSL structure");

    bio_read = bio_write = NULL;
    verify_depth = -2;
    verify = -1;
    ciphers = NULL;
    for (i=0; i<items; i+=2) {
        name = SvPV(args[i], len);
        value = args[i+1];
        if (len >= 6) switch(name[0]) {
          case 'c': case 'C':
            if (LOW_EQ(name, len, "ciphers")) {
                STRLEN l;
                if (ciphers) croak("Multiple ciphers arguments");
                ciphers = SvPV(value, len);
                /* Check that the string doesn't contain \0 and isn't UTF8 */
                for (l=0; l<len;l++) {
                    /* Change this for EBCDIC --Ton */
                    if (ciphers[l] < ' ' || ciphers[l] > 'z')
                        croak("Invalid character (0x%02x) in ciphers string",
                              ciphers[l]);
                }
                if (ciphers[len])
                    croak("Assert: internal perl string does not end in \\0");
                if (SSL_set_cipher_list(ssl->ssl, ciphers) != 1)
                    croak("Could not set ciphers to '%"SVf"'", value);
                goto OK;
            }
            break;
          case 'r': case 'R':
            if (LOW_EQ(name, len, "read_bio")) {
                if (bio_read) croak("Multiple read_bio arguments");
                bio_read = value;
                goto OK;
             }
            break;
          case 'v': case 'V':
            if (LOW_EQ(name, len, "verify_depth")) {
                if (verify_depth != 2)
                    croak("Multiple verify_depth arguments");

                if (SvMAGICAL(value)) value = MORTALCOPY(value);
                if (SvOK(value)) {
                    IV depth = SvIV(value);
                    if (depth < 0) croak("Negative verify_depth");
                    if (depth > MAX_VERIFY_DEPTH)
                        croak("verify_depth out of range");
                    verify_depth = depth;
                } else {
                    verify_depth = -1;
                }
                goto OK;
            }
            if (LOW_EQ(name, len, "verify")) {
                const char *v;

                if (verify >= 0) croak("Multiple verify arguments");
                v = SvPV(value, len);
                if (len >= 4) switch(v[0]) {
                  case 'n': case 'N':
                    if (LOW_EQ(v, len, "none")) {
                        verify = SSL_VERIFY_NONE;
                        goto OK;
                    }
                    break;
                  case 'p': case 'P':
                    if (LOW_EQ(v, len, "optional")) {
                        verify = SSL_VERIFY_PEER;
                        goto OK;
                    }
                    if (LOW_EQ(v, len, "mandatory")) {
                        if (direction != SERVER)
                            croak("peer_mandatory is only valid for SSL servers");
                        verify =
                            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
                        goto OK;
                    }
                    break;
                }
                croak("Unknown verify value '%"SVf"'", value);
            }
            break;
          case 'w': case 'W':
            if (LOW_EQ(name, len, "write_bio")) {
                if (bio_write) croak("Multiple write_bio arguments");
                bio_write = value;
                goto OK;
            }
            break;
        }
        croak("Unknown option '%"SVf"'", args[i]);
      OK:;
    }

    bio = SV_TO_BIO(bio_read, "read_bio");
    SvREFCNT_inc(bio_read);
    ssl->bio_read = bio_read;
    BIO_read = bio->bio;

    bio = SV_TO_BIO(bio_write, "write_bio");
    SvREFCNT_inc(bio_write);
    ssl->bio_write = bio_write;
    BIO_write = bio->bio;

    CRYPTO_add(&BIO_read->references, 1, CRYPTO_LOCK_BIO);
    if (BIO_write != BIO_read)
        CRYPTO_add(&BIO_write->references, 1, CRYPTO_LOCK_BIO);
    SSL_set_bio(ssl->ssl, BIO_read, BIO_write);

    if (verify == -1) verify = SSL_VERIFY_PEER;
    SSL_set_verify(ssl->ssl, verify, verify_callback);

    if (verify_depth == -2) verify_depth = -1;
    SSL_set_verify_depth(ssl->ssl, (int) verify_depth);

    if (SSL_set_ex_data(ssl->ssl, ssl_wrapper_index, ssl) != 1)
        croak("Could not set SSL user data");

    if (direction == SERVER) {
        rc = SSL_accept(ssl->ssl);
        if (rc != 1) {
            ssl_croak(ssl, "accept", rc);
            return NULL;
        }
        ssl->mode = SERVER;
    } else if  (direction == CLIENT) {
        rc = SSL_connect(ssl->ssl);
        if (rc != 1) {
            ssl_croak(ssl, "connect", rc);
            return NULL;
        }
        ssl->mode = CLIENT;
    } else croak("Assert: Unknown direction %d", direction);

    return sv_ssl;
}

XS(boot_WEC__SSL__Bio);
XS(boot_WEC__SSL__Digest);
XS(boot_WEC__SSL__Cipher);
XS(boot_WEC__SSL__X509);
XS(boot_WEC__SSL__Engine);
XS(boot_WEC__SSL__Rand);
XS(boot_WEC__SSL__BigInt);

MODULE = WEC::SSL::SSL		PACKAGE = WEC::SSL::SSL
PROTOTYPES: ENABLE

SV *
get(wec_ssl ssl, int len)
  PREINIT:
    STRLEN dummy;
    char *buf;
    int rc;
  CODE:
    if (len < 0) croak("Negative length");
    RETVAL = NEWSV(__LINE__ % 1000, len);
    sv_setpvn(RETVAL, "", 0);
    buf = SvPV(RETVAL, dummy);
    rc = SSL_read(ssl->ssl, buf, len);
    if (rc <= 0) {
        SvREFCNT_dec(RETVAL);
        ssl_croak(ssl, "read", rc);
    }
    SvCUR_set(RETVAL, rc);
    buf[rc] = 0;
  OUTPUT:
    RETVAL

SV *
write(wec_ssl ssl, SV *bufsv)
  PREINIT:
    int rc;
  CODE:
    /* if (bio->chain) croak("Direct I/O on a chained BIO"); */
    rc = ssl_write(aTHX_ ssl->ssl, bufsv);
    if (rc <= 0) ssl_croak(ssl, "write", rc);
    RETVAL = rc >= 0 ? newSViv(rc) : NEWSV(__LINE__ % 1000, 0);
  OUTPUT:
    RETVAL

void
DESTROY(wec_ssl ssl)
  PPCODE:
    warn("Freeing SSL %p", ssl);
    /* No SSL_clear should be needed since we won't do a new connect */
    if (ssl->ssl) SSL_free(ssl->ssl);
    if (ssl->bio_read)  SvREFCNT_dec(ssl->bio_read);
    if (ssl->bio_write) SvREFCNT_dec(ssl->bio_write);
    if (ssl->context) SvREFCNT_dec(ssl->context);
    Safefree(ssl);

MODULE = WEC::SSL::SSL		PACKAGE = WEC::SSL::SSLContext
void
new(char *class, ...)
  PREINIT:
    wec_ssl_context ssl_context;
    SV *object;
    const char *name, *chain_file, *private_key_file, *ciphers;
    STRLEN len;
    I32 i;
    SV *value;
    int rc, verify_defaults;
  PPCODE:
    if (items % 2  == 0) croak("Odd number of arguments");

    New(__LINE__ % 1000, ssl_context, 1, struct wec_ssl_context);
    ssl_context->ctx = NULL;
    ssl_context->error_cert = NULL;
    object = sv_newmortal();
    sv_setref_pv(object, class, (void*) ssl_context);

    ssl_context->ctx = SSL_CTX_new(SSLv23_method());
    if (!ssl_context->ctx) croak("Could not create an SSL_CTX object");

    chain_file = private_key_file = NULL;
    ciphers = NULL;
    verify_defaults = 0;
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 8) switch(name[0]) {
          case 'c': case 'C':
            if (LOW_EQ(name, len, "chain_file")) {
                if (chain_file) croak("Multiple chain_file arguments");
                chain_file = SV_FILE(value);
                goto OK;
            }
            if (LOW_EQ(name, len, "ciphers")) {
                STRLEN l;
                if (ciphers) croak("Multiple ciphers arguments");
                ciphers = SvPV(value, len);
                /* Check that the string doesn't contain \0 and isn't UTF8 */
                for (l=0; l<len;l++) {
                    /* Change this for EBCDIC --Ton */
                    if (ciphers[l] < ' ' || ciphers[l] > 'z')
                        croak("Invalid character (0x%02x) in ciphers string",
                              ciphers[l]);
                }
                if (ciphers[len])
                    croak("Assert: internal perl string does not end in \\0");
                if (SSL_CTX_set_cipher_list(ssl_context->ctx, ciphers) != 1)
                    croak("Could not set ciphers to '%"SVf"'", value);
                goto OK;
            }
            break;
          case 'p': case 'P':
            if (LOW_EQ(name, len, "private_key_file")) {
                if (private_key_file)
                    croak("Multiple private_key_file arguments");
                private_key_file = SV_FILE(value);
                goto OK;
            }
            break;
          case 'v': case 'V':
            if (LOW_EQ(name, len, "verification_file")) {
                const char *file = SV_FILE(value);
                rc = SSL_CTX_load_verify_locations(ssl_context->ctx,
                                                   file, NULL);
                if (rc != 1)
                    croak("Could not load verification_file '%s'", file);
                goto OK;
            }
            if (LOW_EQ(name, len, "verification_directory")) {
                const char *dir = SV_FILE(value);
                rc = SSL_CTX_load_verify_locations(ssl_context->ctx,
                                                   NULL, dir);
                if (rc != 1)
                    croak("Could not load verification_directory '%s'", dir);
                goto OK;
            }
            if (LOW_EQ(name, len, "default_verification_paths")) {
                if (verify_defaults)
                    croak("multiple default_verification_paths arguments");
                verify_defaults = SvTRUE(value) ? 1 : -1;
                if (verify_defaults > 0 &&
                    SSL_CTX_set_default_verify_paths(ssl_context->ctx) != 1)
                    croak("Could not set default verification paths");
                goto OK;
            }
            break;
        }
        croak("Unknown option '%"SVf"'", ST(i));
      OK:;
    }

    if (chain_file) {
        if (SSL_CTX_use_certificate_chain_file(ssl_context->ctx,
                                               chain_file) != 1)
            croak("Error loading certificate from file '%s'", chain_file);
    }
    if (private_key_file) {
        if (SSL_CTX_use_PrivateKey_file(ssl_context->ctx, private_key_file,
                                        SSL_FILETYPE_PEM) != 1)
            croak("Error loading private key from file");
    }
    if (SSL_CTX_set_cipher_list(ssl_context->ctx, DEFAULT_CIPHERS) != 1)
        croak("Could not set ciphers to '%s'", DEFAULT_CIPHERS);

    /* Enable all bug-compatibility workarounds. Don't do SSL v2 */
    SSL_CTX_set_options(ssl_context->ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);

    XPUSHs(object);

void
add_verification_file(wec_ssl_context ssl_context, SV *path)
  PREINIT:
    const char *file;
    int rc;
  PPCODE:
    file = SV_FILE(path);
    rc = SSL_CTX_load_verify_locations(ssl_context->ctx, file, NULL);
    if (rc != 1) croak("Could not load verification_file '%s'", file);

void
add_verification_directory(wec_ssl_context ssl_context, SV *path)
  PREINIT:
    const char *dir;
    int rc;
  PPCODE:
    dir = SV_FILE(path);
    rc = SSL_CTX_load_verify_locations(ssl_context->ctx, NULL, dir);
    if (rc != 1) croak("Could not load verification_directory '%s'", dir);

void
add_default_verification_paths(wec_ssl_context ssl_context)
  PREINIT:
    int rc;
  PPCODE:
    rc = SSL_CTX_set_default_verify_paths(ssl_context->ctx);
    if (rc != 1) croak("Could not set default verification paths");

void
connect(SV *sv_ssl_context, ...)
  PREINIT:
    SV *sv_ssl;
  PPCODE:
    sv_ssl = ssl_options(aTHX_ sv_ssl_context, &ST(1), items-1, CLIENT);
    if (sv_ssl) XPUSHs(sv_ssl);
    else XSRETURN_UNDEF;

void
accept(SV *sv_ssl_context, ...)
  PREINIT:
    SV *sv_ssl;
  PPCODE:
    sv_ssl = ssl_options(aTHX_ sv_ssl_context, &ST(1), items-1, SERVER);
    if (sv_ssl) XPUSHs(sv_ssl);
    else XSRETURN_UNDEF;

void
verify_error(wec_ssl_context ssl_context)
  PREINIT:
    SV *error;
    const char *error_string;
  PPCODE:
    if (!ssl_context->error_cert) XSRETURN_EMPTY;

    /* construct a dualvar for the error code */
    error = sv_newmortal();
    SvUPGRADE(error,SVt_PVNV);
    error_string = X509_verify_cert_error_string(ssl_context->error_code);
    if (!error_string)
        croak("Assert: No error string for code %d", ssl_context->error_code);
    sv_setpv(error, error_string);
    SvIVX(error) = ssl_context->error_code;
    SvIOK_on(error);

    XPUSHs(sv_2mortal(newRV_inc(ssl_context->error_cert)));
    XPUSHs(sv_2mortal(newSVuv(ssl_context->error_depth)));
    XPUSHs(error);

void
DESTROY(wec_ssl_context ssl_context)
  PPCODE:
    warn("Freeing SSL context %p", ssl_context);
    if (ssl_context->ctx) SSL_CTX_free(ssl_context->ctx);
    if (ssl_context->error_cert) SvREFCNT_dec(ssl_context->error_cert);
    Safefree(ssl_context);

BOOT:
    init_utils();
    boot(aTHX);
