#include "wec_ssl.h"
#include <limits.h>

INIT_UTILS

MODULE = WEC::SSL::Cipher		PACKAGE = WEC::SSL::CipherContext
PROTOTYPES: ENABLE

int
key_length(wec_cipher_context cipher_context)
  CODE:
    RETVAL = EVP_CIPHER_CTX_key_length(&cipher_context->ctx);
  OUTPUT:
    RETVAL

int
iv_length(wec_cipher_context cipher_context)
  CODE:
    RETVAL = EVP_CIPHER_CTX_iv_length(&cipher_context->ctx);
  OUTPUT:
    RETVAL

int
block_size(wec_cipher_context cipher_context)
  CODE:
    RETVAL = EVP_CIPHER_CTX_block_size(&cipher_context->ctx);
  OUTPUT:
    RETVAL

void
DESTROY(wec_cipher_context cipher_context)
  PPCODE:
    EVP_CIPHER_CTX_cleanup(&cipher_context->ctx);
    Safefree(cipher_context);

MODULE = WEC::SSL::Cipher		PACKAGE = WEC::SSL::Decrypt

void
new(char *class, ...)
  ALIAS:
    WEC::SSL::Encrypt::new = 1
  PREINIT:
    I32 i;
    ENGINE *engine;
    const EVP_CIPHER *cipher;
    bool has_key, has_iv;
    char key[EVP_MAX_KEY_LENGTH];
    char iv[EVP_MAX_IV_LENGTH];
    const char *val, *name;
    SV *value, *object;
    STRLEN len;
    wec_cipher_context cipher_context;
    int rc;
  PPCODE:
    if (items % 2 == 0) croak("Odd number of arguments");
    has_key = has_iv = 0;
    cipher = NULL;
    engine = NULL;
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 2) switch(name[0]) {
          case 'c': case 'C':
            if (TRY_CIPHER(cipher, name, len, value)) goto OK;
            break;
          case 'e': case 'E':
            if (LOW_EQ(name, len, "engine")) {
                if (engine) croak("Multiple engine arguments");
                croak("Engines not implemented yet");
                goto OK;
            }
            break;
          case 'i': case 'I':
            if (LOW_EQ(name, len, "iv")) {
                if (has_iv) croak("Multiple iv arguments");
                val = SvPV(value, len);
                if (SvUTF8(value)) {
                    len = UTF8_COPY(iv, sizeof(iv), val, len);
                    Zero(iv+len, sizeof(iv)-len, char);
                } else if (len >= sizeof(iv))
                    Copy(val, iv, sizeof(iv), char);
                else {
                    Copy(val, iv, len, char);
                    Zero(iv+len, sizeof(iv)-len, char);
                }
                has_iv = 1;
                goto OK;
            }
            break;
          case 'k': case 'K':
            if (LOW_EQ(name, len, "key")) {
                if (has_key) croak("Multiple key arguments");
                val = SvPV(value, len);
                /* Should only copy as much as needed --Ton */
                if (SvUTF8(value)) {
                    len = UTF8_COPY(key, sizeof(key), val, len);
                    Zero(key+len, sizeof(key)-len, char);
                } else if (len >= sizeof(key))
                    Copy(val, key, sizeof(key), char);
                else {
                    Copy(val, key, len, char);
                    Zero(key+len, sizeof(key)-len, char);
                }
                has_key = 1;
                goto OK;
            }
            break;
        }
        croak("Unknown option '%"SVf"'", ST(i));
      OK:;
    }
    if (!cipher) croak("No cipher argument");
    if (!has_key) croak("No key argument");

    Newx(cipher_context, 1, struct wec_cipher_context);
    object = sv_newmortal();
    sv_setref_pv(object, class, (void*) cipher_context);

    EVP_CIPHER_CTX_init(&cipher_context->ctx);
    if (ix) {
        rc = EVP_EncryptInit_ex(&cipher_context->ctx, cipher, engine,
                                key, has_iv ? iv : NULL);
        if (rc != 1) croak("Error initializing encryption object");
    } else {
        rc = EVP_DecryptInit_ex(&cipher_context->ctx, cipher, engine,
                                key, has_iv ? iv : NULL);
        if (rc != 1) croak("Error initializing decryption object");
    }
    cipher_context->finished = 0;

    XPUSHs(object);

SV *
update(wec_cipher_context cipher_context, SV *sv_string)
  ALIAS:
    WEC::SSL::Encrypt::update = 1
  PREINIT:
    STRLEN len, dummy_len;
    const unsigned char *string;
    unsigned char *out;
    int nr_out, rc;
  CODE:
    if (cipher_context->finished) croak("Cipher object is finished");
    string = SV_BYTES(sv_string, len);
    if (len > INT_MAX - EVP_CIPHER_CTX_block_size(&cipher_context->ctx))
        croak("Input length out of range");
    RETVAL = newSV(len+EVP_CIPHER_CTX_block_size(&cipher_context->ctx));
    sv_setpvn(RETVAL, "", 0);
    out = SvPV(RETVAL, dummy_len);
    if (ix) {
        rc = EVP_EncryptUpdate(&cipher_context->ctx, out, &nr_out, string, (int) len);
        if (rc != 1) {
            SvREFCNT_dec(RETVAL);
            croak("Could not encrypt data");
        }
    } else {
        rc = EVP_DecryptUpdate(&cipher_context->ctx, out, &nr_out, string, (int) len);
        if (rc != 1) {
            SvREFCNT_dec(RETVAL);
            croak("Could not decrypt data");
        }
    }
    SvCUR_set(RETVAL, nr_out);
    out[nr_out] = 0;
  OUTPUT:
    RETVAL

SV *
finish(wec_decrypt cipher_context)
  PREINIT:
    int nr_out, rc;
    unsigned char final[EVP_MAX_BLOCK_LENGTH];
  CODE:
    if (cipher_context->finished) croak("Cipher object is finished");
    rc = EVP_DecryptFinal_ex(&cipher_context->ctx, final, &nr_out);
    if (rc != 1) croak("Could not finish decrypting data");
    RETVAL = newSVpvn(final, nr_out);
    cipher_context->finished = 1;
  OUTPUT:
    RETVAL

MODULE = WEC::SSL::Cipher		PACKAGE = WEC::SSL::Encrypt

SV *
finish(wec_encrypt cipher_context)
  PREINIT:
    int nr_out, rc;
    unsigned char final[EVP_MAX_BLOCK_LENGTH];
  CODE:
    if (cipher_context->finished) croak("Cipher object is finished");
    rc = EVP_EncryptFinal_ex(&cipher_context->ctx, final, &nr_out);
    if (rc != 1) croak("Could not finish encrypting data");
    RETVAL = newSVpvn(final, nr_out);
    cipher_context->finished = 1;
  OUTPUT:
    RETVAL

BOOT:
    init_utils();
