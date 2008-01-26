#include "wec_ssl.h"

INIT_UTILS

static int bio_write(pTHX_ BIO *bio, SV *bufsv) {
    STRLEN len, retlen;
    char *buf, *buf_end, *from;
    U8 *temp, *to;
    int rc;
    UV ch;

    buf = SvPV(bufsv, len);
    if (SvUTF8(bufsv)) {
        U32 utf8_flags  = ckWARN(WARN_UTF8) ? 0 : UTF8_ALLOW_ANY;
        New(__LINE__ % 1000, temp, len, U8);
        to = temp;
        buf_end = buf + len;
        for (from=buf; from < buf_end; from+=retlen) {
            ch = utf8n_to_uvchr((U8*) from, buf_end-from, &retlen, utf8_flags);
            if (retlen == (STRLEN) -1 || retlen == 0) {
                Safefree(temp);
                croak("Malformed UTF-8 string in write");
            }
            if (ch >= 0x100) {
                Safefree(temp);
                croak("UTF-8 string can't be downgraded");
            }
            *to++ = ch;
        }
        rc = BIO_write(bio, (char *) temp, to-temp);
        Safefree(temp);
    } else rc = BIO_write(bio, buf, len);
    return rc;
}

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio
PROTOTYPES: ENABLE

SV *
get(wec_bio bio, SV *length)
  PREINIT:
    STRLEN dummy;
    char *buf;
    int rc, len;
  CODE:
    len = GET_INT(length, "length");
    /* if (bio->chain) croak("Direct I/O on a chained BIO"); */
    if (len < 0) croak("Negative length");
    RETVAL = NEWSV(__LINE__ % 1000, len);
    sv_setpvn(RETVAL, "", 0);
    buf = SvPV(RETVAL, dummy);
    rc = BIO_read(bio->bio, buf, len);
    if (rc < 0) {
        if (rc < -1) croak("BIO_read not valid for this BIO");
        SvREFCNT_dec(RETVAL);
        XSRETURN_UNDEF;
    }
    if (rc) SvCUR_set(RETVAL, rc);
    buf[rc] = 0;
  OUTPUT:
    RETVAL

SV *
gets(wec_bio bio, SV *length)
  PREINIT:
    STRLEN dummy;
    char *buf;
    int rc, len;
  CODE:
    /* if (bio->chain) croak("Direct I/O on a chained BIO"); */
    len = GET_INT(length, "length");
    if (len < 0) croak("Negative length");
    RETVAL = NEWSV(__LINE__ % 1000, len);
    sv_setpvn(RETVAL, "", 0);
    buf = SvPV(RETVAL, dummy);
    rc = BIO_gets(bio->bio, buf, len);
    if (rc <= 0) {
        if (rc < -1) croak("BIO_gets not valid for this BIO");
        SvREFCNT_dec(RETVAL);
        XSRETURN_UNDEF;
    }
    if (rc) SvCUR_set(RETVAL, rc);
    buf[rc] = 0;
  OUTPUT:
    RETVAL

SV *
write(wec_bio bio, SV *bufsv)
  PREINIT:
    int rc;
  CODE:
    /* if (bio->chain) croak("Direct I/O on a chained BIO"); */
    rc = bio_write(aTHX_ bio->bio, bufsv);
    if (rc < -1) croak("BIO_write not valid for this BIO");
    RETVAL = rc >= 0 ? newSViv(rc) : NEWSV(__LINE__ % 1000, 0);
  OUTPUT:
    RETVAL

void
flush(wec_bio bio)
  PREINIT:
    int rc;
  PPCODE:
    /* if (bio->chain) croak("Direct I/O on a chained BIO"); */
    rc = BIO_flush(bio->bio);
    if (rc < 0) {
        if (rc < -1) croak("BIO_flush not valid for this BIO");
        XSRETURN(0);
    }
    XPUSHs(rc ? &PL_sv_yes : &PL_sv_no);

void
should_read(wec_bio bio)
  PPCODE:
    XPUSHs(BIO_should_read(bio->bio) ? &PL_sv_yes : &PL_sv_no);

void
should_write(wec_bio bio)
  PPCODE:
    XPUSHs(BIO_should_write(bio->bio) ? &PL_sv_yes : &PL_sv_no);

void
should_io_special(wec_bio bio)
  PPCODE:
    XPUSHs(BIO_should_io_special(bio->bio) ? &PL_sv_yes : &PL_sv_no);

void
should_retry(wec_bio bio)
  PPCODE:
    XPUSHs(BIO_should_retry(bio->bio) ? &PL_sv_yes : &PL_sv_no);

void
eof(wec_bio bio)
  PPCODE:
    XPUSHs(BIO_eof(bio->bio) ? &PL_sv_yes : &PL_sv_no);

int
retry_type(wec_bio bio)
  CODE:
    RETVAL = BIO_retry_type(bio->bio);
  OUTPUT:
    RETVAL

UV
read_pending(wec_bio bio)
  PREINIT:
    size_t pending;
  CODE:
    pending = BIO_ctrl_pending(bio->bio);
    RETVAL = pending;
  OUTPUT:
    RETVAL

UV
write_pending(wec_bio bio)
  PREINIT:
    size_t pending;
  CODE:
    pending = BIO_ctrl_wpending(bio->bio);
    RETVAL = pending;
  OUTPUT:
    RETVAL

void
DESTROY(wec_bio bio)
  PPCODE:
    /* bio_free actually can't fail if you don't pass it a NULL argument */
    BIO_free(bio->bio);
    Safefree(bio);

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio::File

SV *
new(char *class, char *filename, char *mode)
  PREINIT:
    BIO *bio;
    wec_bio_file bio_file;
  CODE:
    bio = BIO_new_file(filename, mode);
    if (!bio) croak("Could not create BIO_file");

    New(__LINE__ % 1000, bio_file, 1, struct wec_bio);
    bio_file->bio = bio;
    bio_file->chain = NULL;
    bio_file->ssl = NULL;

    RETVAL = NEWSV(__LINE__ % 1000, 0);
    sv_setref_pv(RETVAL, class, (void*)bio_file);
  OUTPUT:
    RETVAL

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio::Socket

SV *
new(char *class, SV *socket)
  PREINIT:
    BIO *bio;
    wec_bio_socket bio_socket;
    int fd;
    GV *gv;
    IO *io;
    SV *pad_tmp[2];
    struct op pad_op;
    AV pad_av;
    XPVAV pad_vav;
  CODE:
    FAKE_PAD();
    /* Is this the best ? */
    pad_op.op_flags = 0;
    /* Allow literal strings like STDOUT, avoid save_gp() */
    pad_op.op_private = 0;

    XPUSHs(socket);
    PUTBACK;
    PL_ppaddr[OP_RV2GV](aTHX);
    SPAGAIN;
    gv = (GV *) POPs;
    if (!gv) croak("Assert: NULL GLOB pointer");

    pad_op.op_private = 1;
    PUSHs((SV *) gv);
    PUTBACK;
    PL_ppaddr[OP_FILENO](aTHX);
    SPAGAIN;
    socket = POPs;
    if (!socket) croak("Assert: NULL FD pointer");
    if (SvMAGICAL(socket)) socket = MORTALCOPY(socket);
    if (!SvOK(socket)) croak("Undefined filedescriptor");
    fd = SvIV(socket);

    if (SvTYPE(gv) != SVt_PVGV) croak("Not a GLOB reference");
    io = GvIOp(gv);
    if (!io) croak("No IO reference in GLOB");
    if (SvTYPE(io) != SVt_PVIO) croak("Not an IO reference");

    bio = BIO_new_socket(fd, BIO_NOCLOSE);
    if (!bio) croak("Could not create BIO_socket");

    New(__LINE__ % 1000, bio_socket, 1, struct wec_bio_socket);
    bio_socket->bio = bio;
    bio_socket->chain = NULL;
    bio_socket->ssl = NULL;
    SvREFCNT_inc(io);
    bio_socket->socket = io;

    RETVAL = NEWSV(__LINE__ % 1000, 0);
    sv_setref_pv(RETVAL, class, (void*)bio_socket);
  OUTPUT:
    RETVAL

void
DESTROY(wec_bio_socket bio_socket)
  PPCODE:
    SvREFCNT_dec(bio_socket->socket);
    BIO_free(bio_socket->bio);
    Safefree(bio_socket);

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio::Buffer

SV *
new(char *class)
  PREINIT:
    BIO *bio;
    wec_bio_buffer bio_buffer;
  CODE:
    bio = BIO_new(BIO_f_buffer());
    if (!bio) croak("Could not create BIO_buffer");

    New(__LINE__ % 1000, bio_buffer, 1, struct wec_bio);
    bio_buffer->bio = bio;
    bio_buffer->chain = NULL;
    bio_buffer->ssl = NULL;

    RETVAL = NEWSV(__LINE__ % 1000, 0);
    sv_setref_pv(RETVAL, class, (void*)bio_buffer);
  OUTPUT:
    RETVAL

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio::Pair

SV *
new(char *class, long size=0)
  PREINIT:
    BIO *bio;
    wec_bio_pair bio_pair;
    int rc;
  CODE:
    bio = BIO_new(BIO_s_bio());
    if (!bio) croak("Could not create BIO_pair");
    if (size) {
      rc = BIO_set_write_buf_size(bio, size);
      if (rc != 1) {
	BIO_free(bio);
	croak("Could not set buffersize for BIO_pair");
      }
    }

    New(__LINE__ % 1000, bio_pair, 1, struct wec_bio_pair);
    bio_pair->bio = bio;
    bio_pair->chain = NULL;
    bio_pair->ssl = NULL;
    bio_pair->peer  = NULL;

    RETVAL = NEWSV(__LINE__ % 1000, 0);
    sv_setref_pv(RETVAL, class, (void*)bio_pair);
  OUTPUT:
    RETVAL

void
join(wec_bio_pair bio_pair1, wec_bio_pair bio_pair2)
  PREINIT:
    int rc;
  PPCODE:
    if (bio_pair1->peer) croak("bio_pair1 is already joined");
    if (bio_pair2->peer) croak("bio_pair2 is already joined");
    if (bio_pair1 == bio_pair2) croak("Can't self join");
    rc = BIO_make_bio_pair(bio_pair1->bio, bio_pair2->bio);
    if (rc != 1) croak("Could not join");
    bio_pair1->peer = bio_pair2;
    bio_pair2->peer = bio_pair1;

void
split(wec_bio_pair bio_pair)
  PREINIT:
    int rc;
  PPCODE:
    if (!bio_pair->peer) croak("BIO_pair is not joined");
    rc = BIO_destroy_bio_pair(bio_pair->bio);
    if (rc != 1) croak("Could not split");
    bio_pair->peer->peer = NULL;
    bio_pair->peer = NULL;

void
DESTROY(wec_bio_pair bio)
  PPCODE:
    BIO_free(bio->bio);
    if (bio->peer) bio->peer->peer = NULL;
    Safefree(bio);

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio::B64

SV *
new(char *class)
  PREINIT:
    BIO *bio;
    wec_bio_b64 bio_b64;
  CODE:
    bio = BIO_new(BIO_f_base64());
    if (!bio) croak("Could not create BIO_b64");

    New(__LINE__ % 1000, bio_b64, 1, struct wec_bio);
    bio_b64->bio = bio;
    bio_b64->chain = NULL;
    bio_b64->ssl = NULL;

    RETVAL = NEWSV(__LINE__ % 1000, 0);
    sv_setref_pv(RETVAL, class, (void*)bio_b64);
  OUTPUT:
    RETVAL

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio::Memory

SV *
new(char *class)
  PREINIT:
    BIO *bio;
    wec_bio_memory bio_memory;
  CODE:
    bio = BIO_new(BIO_s_mem());
    if (!bio) croak("Could not create BIO_mem");

    New(__LINE__ % 1000, bio_memory, 1, struct wec_bio);
    bio_memory->bio = bio;
    bio_memory->chain = NULL;
    bio_memory->ssl = NULL;

    RETVAL = NEWSV(__LINE__ % 1000, 0);
    sv_setref_pv(RETVAL, class, (void*)bio_memory);
  OUTPUT:
    RETVAL

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio::Cipher
MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::Bio::Decrypt

SV *
new(char *class, ...)
  ALIAS:
    WEC::SSL::Bio::Encrypt::new = 1
  PREINIT:
    BIO *bio;
    I32 i;
    wec_bio_cipher bio_cipher;
    bool has_key, has_iv;
    char key[EVP_MAX_KEY_LENGTH];
    char iv[EVP_MAX_IV_LENGTH];
    SV *value;
    char *name, *val;
    const EVP_CIPHER *cipher;
    STRLEN len;
  CODE:
    /* Should resuse WEC::SSL::Encrypt new code --Ton */
    has_key = has_iv = 0;
    cipher = NULL;
    if (items % 2 == 0) croak("odd number of arguments");
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 2) switch(name[0]) {
          case 'c': case 'C':
            if (TRY_CIPHER(cipher, name, len, value)) goto OK;
            break;
          case 'i': case 'I':
            if (LOW_EQ(name, len, "iv")) {
                if (has_iv) croak("Multiple iv arguments");
                val = SvPV(value, len);
                if (SvUTF8(value)) {
                    len = UTF8_COPY( iv, sizeof(iv), val, len);
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
                if (SvUTF8(ST(i+1))) {
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

    bio = BIO_new(BIO_f_cipher());
    if (!bio) croak("Could not create BIO_cipher");

    New(__LINE__ % 1000, bio_cipher, 1, struct wec_bio);
    bio_cipher->bio = bio;
    bio_cipher->chain = NULL;
    bio_cipher->ssl = NULL;
    BIO_set_cipher(bio_cipher->bio, cipher, key, has_iv ? iv : NULL, ix);

    RETVAL = NEWSV(__LINE__ % 1000, 0);
    sv_setref_pv(RETVAL, class, (void*)bio_cipher);
  OUTPUT:
    RETVAL

void
status(wec_bio_decrypt bio)
  PPCODE:
    XPUSHs(BIO_get_cipher_status(bio->bio) ? &PL_sv_yes : &PL_sv_no);

MODULE = WEC::SSL::Bio		PACKAGE = WEC::SSL::BioChain

SV *
new(char *class)
  PREINIT:
    wec_bio_chain bio_chain;
  CODE:
    New(__LINE__ % 1000, bio_chain, 1, struct wec_bio_chain);
    bio_chain->nr_bio = 0;
    bio_chain->nr_allocated = 0;
    bio_chain->bio = NULL;
    bio_chain->ssl = NULL;
    RETVAL = NEWSV(__LINE__ % 1000, 0);
    sv_setref_pv(RETVAL, class, (void*)bio_chain);
  OUTPUT:
    RETVAL

void
DESTROY(wec_bio_chain bio_chain)
  PREINIT:
    SV *bio_sv;
    IV tmp;
    wec_bio bio;
  PPCODE:
    while (bio_chain->nr_bio) {
        bio_sv = bio_chain->bio[bio_chain->nr_bio-1];
        tmp = SvIV(bio_sv);
        bio = INT2PTR(wec_bio, tmp);
        BIO_pop(bio->bio);
        bio->chain = NULL;
        bio_chain->nr_bio--;
        SvREFCNT_dec(bio_sv);
    }
    Safefree(bio_chain->bio);
    Safefree(bio_chain);

void
push(wec_bio_chain bio_chain, ...)
  PREINIT:
    IV tmp;
    wec_bio bio, last_bio, *bios;
    SV *bio_sv;
    I32 i;
  PPCODE:
    if (bio_chain->ssl)
        croak("Attempt to push on a BIO chain that's part of an SSL object");
    items--;
    if (!items) XSRETURN_EMPTY;
    if (bio_chain->nr_bio+items > bio_chain->nr_allocated) {
        UV nr_allocated = 2*bio_chain->nr_bio+items;
        /* User would hardly start a chain if he didn't want at least 2 bios */
        if (nr_allocated < 2) nr_allocated = 2;
        Renew(bio_chain->bio, nr_allocated, SV *);
        bio_chain->nr_allocated = nr_allocated;
    }

    New(__LINE__ %1000, bios, items, wec_bio);
    SAVEFREEPV(bios);
    for (i=0; i<items; i++) {
        bio_sv = ST(i+1);
        if (!SvOK(bio_sv)) croak("Argument %d is undefined", (int) (i+1));
        if (!sv_derived_from(bio_sv, PACKAGE_BASE "::Bio"))
            croak("Argument %d is not of type " PACKAGE_BASE "::Bio", 
                  (int) (i+1));
        if (!SvROK(bio_sv)) 
            croak("Argument %d is not a reference", (int) (i+1));
        bio_chain->bio[bio_chain->nr_bio+i] = bio_sv = SvRV(bio_sv);
        tmp = SvIV(bio_sv);
        bio = INT2PTR(wec_bio, tmp);
        if (bio->chain)
            croak("Argument %d already part of a chain", (int) (i+1));
        if (bio->ssl)
            croak("Argument %d already part of an SSL object", (int) (i+1));
        bios[i] = bio;
    }

    /* First bio pushed could be the very first on this chain */
    if (bio_chain->nr_bio) {
        tmp = SvIV(bio_chain->bio[bio_chain->nr_bio-1]);
        last_bio = INT2PTR(wec_bio, tmp);
        BIO_push(last_bio->bio, bios[0]->bio);
    }
    last_bio = bios[0];
    last_bio->chain = bio_chain;
    bio_sv = bio_chain->bio[bio_chain->nr_bio++];
    SvREFCNT_inc(bio_sv);

    /* All later pushes are sure to have something to connect to */
    for (i=1; i<items; i++) {
        BIO_push(last_bio->bio, bios[i]->bio);
        last_bio = bios[i];
        last_bio->chain = bio_chain;
        bio_sv = bio_chain->bio[bio_chain->nr_bio++];
        SvREFCNT_inc(bio_sv);
    }

SV *
write(wec_bio_chain bio_chain, SV *bufsv)
  PREINIT:
    int rc;
    SV *bio_sv;
    wec_bio bio;
    IV tmp;
  CODE:
    if (bio_chain->ssl)
        croak("Direct I/O on a chain that's part of an SSL object");
    if (!bio_chain->nr_bio) croak("No bios on chain");
    bio_sv = bio_chain->bio[0];
    tmp = SvIV(bio_sv);
    bio = INT2PTR(wec_bio, tmp);
    rc = bio_write(aTHX_ bio->bio, bufsv);
    if (rc < -1) croak("BIO_write not valid for this chain");
    RETVAL = rc >= 0 ? newSViv(rc) : NEWSV(__LINE__ % 1000, 0);
  OUTPUT:
    RETVAL

SV *
head(wec_bio_chain bio_chain)
  CODE:
    if (!bio_chain->nr_bio) XSRETURN_UNDEF;
    RETVAL = newRV_inc(bio_chain->bio[0]);
  OUTPUT:
    RETVAL

SV *
tail(wec_bio_chain bio_chain)
  CODE:
    if (!bio_chain->nr_bio) XSRETURN_UNDEF;
    RETVAL = newRV_inc(bio_chain->bio[bio_chain->nr_bio-1]);
  OUTPUT:
    RETVAL

BOOT:
    init_utils();
