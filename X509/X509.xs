#include "wec_ssl.h"
#include <limits.h>

INIT_UTILS

MODULE = WEC::SSL::X509		PACKAGE = WEC::SSL::X509
PROTOTYPES: ENABLE

SV *
issuer_string(wec_x509 x509)
  PREINIT:
    char buf[1024], *ptr;
    X509_NAME *name;
  CODE:
    name = X509_get_issuer_name(x509->x509);
    if (!name) croak("No issue name");
    ptr = X509_NAME_oneline(name, buf, sizeof(buf));
    if (!ptr) croak("Failed to fetch X509 string");
    RETVAL = newSVpv(ptr, 0);
  OUTPUT:
    RETVAL

SV *
subject_string(wec_x509 x509)
  PREINIT:
    char buf[1024], *ptr;
    X509_NAME *name;
  CODE:
    name = X509_get_subject_name(x509->x509);
    if (!name) croak("No subject name");
    ptr = X509_NAME_oneline(name, buf, sizeof(buf));
    if (!ptr) croak("Failed to fetch X509 string");
    RETVAL = newSVpv(ptr, 0);
  OUTPUT:
    RETVAL

void
PEM_write(wec_x509 x509, ...)
  PREINIT:
    SV *sv_bio;
    wec_bio bio;
    I32 i;
    const char *name;
    STRLEN len, key_len;
    SV *value, *sv_key;
    const EVP_CIPHER *cipher;
    const U8 *key;
    int rc;
  PPCODE:
    if (items % 2 == 0) croak("Odd number of arguments");

    sv_bio = NULL;
    sv_key = NULL;
    cipher = NULL;
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 3) switch(name[0]) {
          case 'b': case 'B':
            if (LOW_EQ(name, len, "bio")) {
                if (sv_bio) croak("Multiple bio arguments");
                sv_bio = value;
                goto OK;
             }
            break;
          case 'c': case 'C':
            if (TRY_CIPHER(cipher, name, len, value)) goto OK;
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

    bio = SV_TO_BIO(sv_bio, "bio");
    if (sv_key) {
        if (!cipher) croak("key without cipher");
        key = SV_BYTES(sv_key, key_len);
        if (key_len > INT_MAX) croak("key length out of range");
        rc = PEM_ASN1_write_bio((int (*)())i2d_X509, PEM_STRING_X509, bio->bio,
                                (char *) x509->x509, cipher,
                                (U8 *) key, (int) key_len, NULL, NULL);
    } else
        rc = PEM_ASN1_write_bio((int (*)())i2d_X509, PEM_STRING_X509, bio->bio,
                                (char *) x509->x509, cipher,
                                NULL, 0, NULL, NULL);

    if (rc != 1) croak("Error writing PEM to bio");

void
DESTROY(wec_x509 x509)
  PPCODE:
    warn("Freeing X509 %p", x509);
    if (x509->x509) X509_free(x509->x509);
    Safefree(x509);

BOOT:
    init_utils();
