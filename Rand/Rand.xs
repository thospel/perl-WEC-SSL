#include "wec_ssl.h"

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

INIT_UTILS

/* Should correspond to the same constant in crypto/rand/randfile.c */
#define RAND_DATA	1024

#define GET_UNI_CHAR(str, str_end, utf8, utf8_flags)	\
	get_uni_char(aTHX_ &str, str_end, utf8, utf8_flags, NULL)
#define GET_UNI_CHAR_RANGE(str, str_end, utf8, utf8_flags, range)	\
	get_uni_char(aTHX_ &str, str_end, utf8, utf8_flags, &range)
static UV get_uni_char(pTHX_ U8 **str, U8 *str_end, U32 utf8, U32 utf8_flags,
                       int *range){
    UV ch;
    STRLEN temp_len;

    if (utf8) {
        ch = utf8n_to_uvuni(*str, str_end-*str, &temp_len, utf8_flags);
        if (temp_len == (STRLEN) -1 || temp_len == 0)
            croak("Malformed UTF-8");
        *str += temp_len;
    } else {
        ch = *(*str)++;
        ch = NATIVE_TO_UNI(ch);
    }
    /* backslash */
    if (ch == 0x5c) {
        if (*str == str_end) croak("Trailing \\");
        if (range) *range = 0;
        if (utf8) {
            ch = utf8n_to_uvchr(*str, str_end-*str, &temp_len, utf8_flags);
            if (temp_len == (STRLEN) -1 || temp_len == 0)
                croak("Malformed UTF-8");
            *str += temp_len;
        } else ch = *(*str)++;

        /* literal escape */
        if (ch < 0x100  && isALNUM((char) ch)) switch(ch) {
          case 'b': ch = '\b'; break;
          case 'n': ch = '\n'; break;
          case 'r': ch = '\r'; break;
          case 'f': ch = '\f'; break;
          case 't': ch = '\t'; break;
          case 'e': ch = ASCII_TO_NATIVE('\033'); break;
          case 'a': ch = ASCII_TO_NATIVE('\007'); break;
          default:
            croak("Unsupported escape sequence \\%c", (int) ch);
        }
        return NATIVE_TO_UNI(ch);
    }
    /* minus */
    if (range) *range = *str < str_end && ch == 0x2d;
    return ch;
}

static NV max_current = 0;
static int bytes_current = 0;

/* Determine the greatest NV that still has integer resolution
   set max_current to that value/256 */
static void max_nv_int(void) {
    volatile NV from, to, try, tmp;
    NV parts[(sizeof(NV)*CHAR_BIT+7)/8];
    U8 bytes[sizeof(parts)/sizeof(NV)];
    int i, n, k, diff;

    to = 1;
    while (tmp = to-1, to-tmp == 1) {
        from = to;
        to *= 2;
    }
    while (to - from >= 1) {
        try = (from+to)/2;
        tmp = try-1;
        if (try - tmp != 1) {
            if (to == try) break;
            to = try;
        } else {
            if (from == try) break;
            from = try;
        }
    }

    /* Determine the byte sequence */
    for (n=0; from >=1; n++) {
        parts[n] = from;
        from /= 256;
    }
    try = 0;
    k = 0;
    for (i=n; --i >= 0; ) {
        try *= 256;
        bytes[i] = diff = parts[i]-try;
        if (diff >= 256) croak("Round error");
        if (diff == 0) k++;
        try = try + bytes[i];
    }
    max_current = (try - bytes[0])/256;
    if (k == n-1 && bytes[k] == 1) n--;
    bytes_current = n-1;
    /* warn("try=%"NVff", max=%"NVff",bytes=%d\n", try, max_current, n); */
}

MODULE = WEC::SSL::Rand		PACKAGE = WEC::SSL::Rand
PROTOTYPES: ENABLE

void
seed(SV *sv_seed, SV *entropy=NULL)
  ALIAS:
    WEC::SSL::Rand::seed_canonical = 1
  PREINIT:
    const char *seed;
    STRLEN len;
    NV entr;
  PPCODE:
    TAINT_NOT;
    if (entropy) {
        entr = SvNV(entropy);
        if (entr < 0) croak("Negative entropy");
        if (ix) seed = SV_CANONICAL(sv_seed, len);
        else seed = SvPV(sv_seed, len);
        if (len > INT_MAX) croak("Seed length out of range");
        if (entr > len) croak("Entropy %"NVgf" greater than string length %"UVuf, entr, (UV) len);
        if (entr) TAINT_PROPER("seed");
        RAND_add(seed, (int) len, (double) entr);
    } else {
        seed = SV_BYTES(sv_seed, len);
        if (len > INT_MAX) croak("Seed length out of range");
        if (len) TAINT_PROPER("seed");
        RAND_seed(seed, (int) len);
    }

void
status()
  PPCODE:
    XPUSHs(RAND_status() ? &PL_sv_yes : &PL_sv_no);

SV *
bytes(SV *length)
  ALIAS:
    WEC::SSL::Rand::pseudo_bytes = 1
  PREINIT:
    char *buf;
    STRLEN dummy_len;
    int rc, len;
  CODE:
    TAINT_NOT;
    len = GET_INT(length, "length");
    if (len < 0) croak("length %d is negative", len);
    RETVAL = newSV(len);
    sv_setpvn(RETVAL, "", 0);
    if (len) {
        if (!RAND_status()) SvTAINTED_on(RETVAL);
        buf = SvPV(RETVAL, dummy_len);
        rc = ix ? RAND_pseudo_bytes(buf, len) : RAND_bytes(buf, len);
        if (rc != 1) {
            SvREFCNT_dec(RETVAL);
            if (rc < 0)
                CRYPTO_CROAK("not supported by the current RAND method");
            CRYPTO_CROAK("Not enough entropy");
        }
        SvCUR_set(RETVAL, len);
        buf[len] = 0;
    }
  OUTPUT:
    RETVAL

void
string(SV *range, SV *length=NULL)
  ALIAS:
    WEC::SSL::Rand::pseudo_string = 1
  PREINIT:
    STRLEN str_len, len, raw_len, rands, diff;
    int rc, is_range, bits, bytes, rest, max_rest;
    UV *from, *f, max_code, ch;
    NV *accu, *a0, *a1, *a, *at, current, test, v, max_v, max_c;
    U8 *str, *ptr, *str_end, buf[64];
    U32 utf8_flags;
    bool utf8;
    SV *result;
  PPCODE:
    TAINT_NOT;

    if (length) {
        ch = GET_UV(length, "length");
        len = ch;
        if (len != ch) croak("length %"UVuf" out of range", ch);
    } else len = 1;

    str = (U8 *) SvPV(range, str_len);
    if (!str_len) croak("Empty range");
    str_end = str + str_len;
    utf8 = SvUTF8(range) ? TRUE : FALSE;

    Newx(from, str_len, UV);
    f = from;
    SAVEFREEPV(f);

    Newx(accu, str_len, NV);
    a = accu;
    SAVEFREEPV(a);

    max_code = 0;
    current = 0;

    utf8_flags = ckWARN(WARN_UTF8) ? 0 : UTF8_ALLOW_ANY;
    while (str < str_end) {
        ch = GET_UNI_CHAR(str, str_end, utf8, utf8_flags);
      TRY_RANGE:
        if (ch > max_code) max_code = ch;
        *a++ = current++;
        *f++ = ch;
        if (str >= str_end) break;
        ch = GET_UNI_CHAR_RANGE(str, str_end, utf8, utf8_flags, is_range);
        if (!is_range) goto TRY_RANGE;
        ch = GET_UNI_CHAR(str, str_end, utf8, utf8_flags);
        if (ch < f[-1]) croak("Invalid range");
        if (ch > max_code) max_code = ch;
        current += ch - f[-1];
    }
    if (current < 1) croak("Assert: Empty range");

    /* Check if we have enough resolution in the NV */
    if (current > max_current)
        croak("Range too wide (%"NVff" values)", current);

    utf8 = max_code >= 0x100;
    if (utf8) {
        rc = UNISKIP(max_code);
        raw_len = len * rc;
        if (raw_len / rc != len) croak("length out of range");
    } else raw_len = len;

    result = newSV(raw_len);
    sv_2mortal(result);
    PUSHs(result);
    sv_setpvn(result, "", 0);
    if (utf8) SvUTF8_on(result);
    if (len) {
        /* count bits */
        test = current-1;
        bits = 0;
        while (test >= ((NV) BN_MASK2 +1)) {
            bits += BN_BITS2;
            test = test / ((NV) BN_MASK2+1);
        }
        if (test - (BN_ULONG) test >= 1) croak("Assert: precission underflow");
        bits += BN_num_bits_word((BN_ULONG) test);
        bytes = (bits+7)/8;

        v = 0;
        max_v = 1;
        /* The real max_c range is current, but we try to add a few bytes
           more, hoping to lower the chance of a retry.
           current == 1 is special since we then want to do NO rand operations
        */
        max_c = current == 1 ? 1 : current * ((NV)INT_MAX+1)/256 - 1;
        if (max_c > max_current) max_c = max_current;

        if (bits && !RAND_status()) SvTAINTED_on(result);
        ptr = str = (U8 *) SvPV(result, str_len);
        rands = 0;
        while (len > 0) {
            if (v < 0 || v > max_v-1) croak("Assert: round error");
            while (max_v < max_c) {
                /* Need more bytes in our current rand */
                if (!rands) {
                    /* Need to generate them first though */
                    rands = len * bytes;
                    if (rands > sizeof(buf) || rands == 0) rands = sizeof(buf);
                    rc = ix ?
                        RAND_pseudo_bytes(buf, (int) rands) :
                        RAND_bytes       (buf, (int) rands);
                    if (rc != 1) {
                        if (rc < 0)
                            CRYPTO_CROAK("not supported by the current RAND method");
                        CRYPTO_CROAK("Not enough entropy");
                    }
                }
                /* Shift in a random bytes */
                v = v * 256 + buf[--rands];
                max_v *= 256;
            }
            /* Now max_v >= current */

            rest     = (int) (    v / current);
            max_rest = (int) (max_v / current);
            if (rest == max_rest) {
                /* Bad luck, we fell into an incomplete current range */
                v     -= rest * current;
                max_v -= rest * current;
                continue;
            }
            test = v - rest * current;
            v     = rest;
            max_v = max_rest;

            /* Test contains our random number.
               Now do a binary search in accu
            */
            a0 = accu;
            a1 = a;
            while ((diff = (a1 - a0) / 2)) {
                at = a0+diff;
                if (test < *at) a1 = at;
                else a0 = at;
            }
            diff = a0-accu;

            ch = from[diff] + (test-*a0);
            if (utf8) ptr = uvuni_to_utf8_flags(ptr, ch, utf8_flags);
            else *ptr++ = UNI_TO_NATIVE(ch);
            len--;
        }
        *ptr = 0;
        SvCUR_set(result, ptr-str);
    }

SV *
filename()
  PREINIT:
    char buf[2049];
    const char *ptr;
  CODE:
    TAINT_NOT;
    buf[sizeof(buf)-1] = 0;
    ptr = RAND_file_name(buf, sizeof(buf)-1);
    if (!ptr) CRYPTO_CROAK("filename too long (longer than %d bytes)",
                           (int) (sizeof(buf)-1));
    RETVAL = newSVpv(ptr, 0);
  OUTPUT:
    RETVAL

void
try_load_file(SV *file, SV *max_bytes=NULL)
  PREINIT:
    const char *filename;
    IV rc;
    UV len;
    SV *result;
  PPCODE:
    filename = SV_FILE(file);
    if (max_bytes) {
        len = GET_UV(max_bytes, "max_bytes");
        if (len > INT_MAX)
            /* Stupid API can only report an int result */
            croak("Requested number of bytes %"UVuf "is out of range", len);
        rc = RAND_load_file(filename, (int) len);
    } else rc = RAND_load_file(filename, -1);
    result = newSViv(rc);
    sv_2mortal(result);
    PUSHs(result);
    SvTAINTED_on(result);

void
try_write_file(SV *file)
  PREINIT:
    const char *filename;
    IV rc;
    SV *result;
  PPCODE:
    TAINT_NOT;
    filename = SV_FILE(file);
    TAINT_PROPER("try_write_file");
    rc = RAND_write_file(filename);
    result = sv_newmortal();
    PUSHs(result);
    if (rc >= 0) sv_setiv(result, rc);

int
try_load_from_egd(SV *path, SV *nr_bytes=NULL)
  PREINIT:
    const char *filename;
    int rc, bytes;
  CODE:
    TAINT_NOT;
    filename = SV_FILE(path);
    TAINT_PROPER("try_load_from_egd");
    /* It's ok if nr_bytes is tainted, if path is trusted the entropy
       addition will be proper */
    if (nr_bytes) {
        bytes = GET_INT(nr_bytes, "nr_bytes");
        if (bytes < 0) croak("nr_bytes %d is negative", bytes);
    } else bytes = 255;
    rc = RAND_egd_bytes(filename, bytes);
    if (rc < 0) CRYPTO_CROAK("EGD request failed");
    RETVAL = rc;
  OUTPUT:
    RETVAL

SV *
try_fetch_from_egd(SV *path, SV *nr_bytes=NULL)
  PREINIT:
    char *buf;
    const char *filename;
    STRLEN dummy_len;
    int rc, bytes;
  CODE:
    TAINT_NOT;
    filename = SV_FILE(path);
    TAINT_PROPER("try_fetch_from_egd");
    if (nr_bytes) {
        bytes = GET_INT(nr_bytes, "nr_bytes");
        if (bytes < 0) croak("nr_bytes %d is negative", bytes);
    } else bytes = 255;
    RETVAL= newSV(bytes);
    sv_setpvn(RETVAL, "", 0);
    buf = SvPV(RETVAL, dummy_len);
    rc = RAND_query_egd_bytes(filename, buf, bytes);
    if (rc < 0) {
        SvREFCNT_dec(RETVAL);
        CRYPTO_CROAK("EGD request failed");
    }
    SvCUR_set(RETVAL, rc);
    buf[rc] = 0;
  OUTPUT:
    RETVAL

int
RAND_DATA()
  CODE:
    RETVAL = RAND_DATA;
  OUTPUT:
    RETVAL

BOOT:
    init_utils();
    max_nv_int();
