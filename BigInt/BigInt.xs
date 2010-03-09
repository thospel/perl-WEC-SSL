#define NEED_sv_2pv_flags
#define NEED_vnewSVpvf
#define NEED_warner
#include "wec_ssl.h"
#include <limits.h>

INIT_UTILS

/* Normal mode, but we should also survive all tests with this set to 0 */
#define RETYPE	1

static const struct wec_bigint ZERO = {
    { 0 },
#if SENSITIVE
    0,
#endif /* SENSITIVE */
};

#if SENSITIVE
# define ZERO_SENSITIVE(x)	(x)->sensitive = 0
#else  /* SENSITIVE */
# define ZERO_SENSITIVE(x)
#endif /* SENSITIVE */

#define NEW_BIGINT(bigint, object)	\
    NEW_CLASS(bigint, object, PACKAGE_BASE "::BigInt")
#define NEW_CLASS(bigint, object, class) STMT_START {	\
    Newx(bigint, 1, struct wec_bigint);			\
    ZERO_SENSITIVE(bigint);				\
    BN_init(&(bigint)->num);				\
    (object) = sv_newmortal();				\
    sv_setref_pv(object, class, (void*) (bigint));	\
    SvTAINT(object);					\
} STMT_END

#define C_DECIMAL(string, context) c_decimal(aTHX_ string, context)

/* Check that the given SV represents a plain integer.
   Return that string
*/
static const char *c_decimal(pTHX_ SV *sv_string, const char *context) {
    const char *string, *ptr, *end;
    STRLEN len;

    string = SvPV(sv_string, len);
    if (len == 0) croak("%s is empty", context);
    end = string + len;
    if (*end) croak("%s perl string does not end in \\0", context);
    while (isSPACE(*string)) string++;
    if (string == end) croak("%s consists of whitespace only", context);
    if (*string == '+') ptr = ++string;
    else if (*string == '-') ptr = string+1;
    else ptr = string;
    if (ptr == end) croak("%s has no digits", context);
    while (isDIGIT(*ptr)) *ptr++;
    if (ptr != end) croak("%s contains non-digit", context);
    return string;
}

#define C_HEX(string, context)     c_hex(aTHX_ string, context)

/* Check that the given SV represents a plain integer in hex notation.
   Return that string
*/
static const char *c_hex(pTHX_ SV *sv_string, const char *context) {
    const char *string, *ptr, *end;
    STRLEN len;

    string = SvPV(sv_string, len);
    if (len == 0) croak("%s is empty", context);
    end = string+len;
    if (*end) croak("%s perl string does not end in \\0", context);
    while (isSPACE(*string)) string++;
    if (string == end) croak("%s consists of whitespace only", context);
    if (string[0] == '+') {
        ptr = ++string;
        len--;
    } else if (string[0] == '-') ptr = string+1;
    else ptr = string;
    if (ptr == end) croak("%s has no digits", context);
    while (1) switch(*ptr) {
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
      case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
        ptr++;
        break;
      case 0:
        if (ptr == end) return string;
        /* fall through */
      default:
        croak("%s contains non-digit", context);
    }
}

static void free_bigint(void *v) {
    wec_bigint bigint = v;
#if SENSITIVE
    if (bigint->sensitive) BN_clear_free(&bigint->num);
    else
#endif /* SENSITIVE */
    BN_free(&bigint->num);
    Safefree(bigint);
}

/* Convert NV to a BIGNUM */
static void big_from_nv (BIGNUM *big, NV dval) {
    int exp, shift;
    NV mantissa;

    mantissa = Perl_frexp(dval < 0 ? -dval : dval, &exp);
    /* Due to previous tests we know mantissa != 0 and exp >= BN_BITS2 */
    if (exp < BN_BITS2) {
        if (exp == 0 && mantissa > 1)
            croak("Cannot convert infinity to an integer");
        if (exp == 0 && mantissa != mantissa)
            croak("Cannot convert NaN to an integer");
        croak("Assert: impossible exponent %d", exp);
    }
    if (!BN_zero(big)) CRYPTO_CROAK("BN_zero error");
    shift = exp - sizeof(mantissa) * CHAR_BIT;
    if (shift >= 0) exp = sizeof(mantissa) * CHAR_BIT;
    while (exp > 0) {
        BN_ULONG ival;
        if (!BN_lshift(big, big, BN_BITS2)) croak("Shift error");
        mantissa *= 1+(double)BN_MASK2;
        ival = mantissa;
        if (!BN_add_word(big, ival)) croak("Add error");
        mantissa -= ival;
        if (mantissa < 0 || mantissa >= 1) croak("Round error");
        exp -= BN_BITS2;
    }
    if (shift >= 0) {
        if (mantissa) croak("Round error");
        if (!BN_lshift(big, big, shift)) croak("Shift error");
    } else if (exp < 0) {
        if (!BN_rshift(big, big, -exp)) croak("Shift error");
    }
    if (dval < 0) BN_set_negative(big, 1);
}

/* mantissa *= 10**exponent */
static void big_exp10(BIGNUM *mantissa, unsigned int exponent) {
    BIGNUM multiplier;
    BN_ULONG mul;
    BN_CTX *ctx;
    int rc, bits;
    unsigned int rev_exp, exp, rest;

    rest = exponent % BN_DEC_NUM;
    exp  = exponent / BN_DEC_NUM;
    if (rest) {
        for (rev_exp = 0, bits = 0; rest != 1; rest >>=1, bits++)
            rev_exp = (rev_exp << 1) + (rest & 1);
        mul = 10;
        while (bits--) {
            mul *= mul;
            if (rev_exp & 1) mul *= 10;
            rev_exp >>= 1;
        }
        if (!BN_mul_word(mantissa, mul)) CRYPTO_CROAK("BN_mul_word error");
    }

    if (exp <= 1) {
        if (exp == 1) {
            if (!BN_mul_word(mantissa, BN_DEC_CONV))
                CRYPTO_CROAK("BN_mul_word error");
        }
        return;
    }

    BN_init(&multiplier);
    if (!BN_set_word(&multiplier, BN_DEC_CONV))
        CRYPTO_CROAK("BN_set_word error");
    ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(&multiplier);
        CRYPTO_CROAK("BN_CTX_new error");
    }
    for (rev_exp = 0, bits = 0; exp != 1; exp >>=1, bits++)
        rev_exp = (rev_exp << 1) + (exp & 1);
    do {
        if (!BN_sqr(&multiplier, &multiplier, ctx)) {
            BN_CTX_free(ctx);
            BN_free(&multiplier);
            CRYPTO_CROAK("BN_sqr error");
        }
        if ((rev_exp & 1) && !BN_mul_word(&multiplier, BN_DEC_CONV)) {
            BN_CTX_free(ctx);
            BN_free(&multiplier);
            CRYPTO_CROAK("BN_mul_word error");
        }
        rev_exp >>= 1;
    } while (--bits);
    rc = BN_mul(mantissa, mantissa, &multiplier, ctx);
    BN_CTX_free(ctx);
    BN_free(&multiplier);
    if (rc != 1) CRYPTO_CROAK("BN_mul error");
}

/* Convert string to a BIGNUM */
static void big_from_pv(pTHX_ BIGNUM *big, SV *sv, const char *context) {
    const char *from, *string, *ptr, *dot, *exp;
    char *tmp;
    IV exponent;
    STRLEN len;
    bool negative;
    int rc;

    /* Don't do magic get, caller should already have done that */
    string = from = SvPV_flags(sv, len, 0);
    if (string[len]) croak("%s perl string does not end in \\0", context);
    while (isSPACE(*string)) string++;
    negative = FALSE;
    if (string[0] == '+') ptr = ++string;
    else if (string[0] == '-') {
        ptr = ++string;
        negative = TRUE;
    } else ptr = string;
    while (isDIGIT(*ptr)) ptr++;
    if (*ptr == '.') {
        dot = ptr++;
        while (isDIGIT(*ptr)) ptr++;
        /* No digits */
        if (ptr == string+1) goto bad_zero;
    } else {
        if (ptr == string) {
            /* No digits */
            if ((ptr[0] == 'i' || ptr[0] == 'I') &&
                (ptr[1] == 'n' || ptr[1] == 'N') &&
                (ptr[2] == 'f' || ptr[2] == 'F'))
                croak("Cannot convert infinity to an integer");
            if ((ptr[0] == 'n' || ptr[0] == 'N') &&
                (ptr[1] == 'a' || ptr[1] == 'A') &&
                (ptr[2] == 'n' || ptr[2] == 'N'))
                croak("Cannot convert NaN to an integer");
          bad_zero:
            if (BN_zero(big) != 1) CRYPTO_CROAK("BN_zero error");
            NOT_A_NUMBER(sv, from, len);
            return;
        }
        dot = NULL;
    }
    exponent = 0;
    exp = ptr;
    if (*ptr == 'e' || *ptr == 'E') {
        const char *digits;

        bool negexp = FALSE;
        ptr++;
        if (*ptr == '+') ptr++;
        else if (*ptr == '-') {
            ptr++;
            negexp = TRUE;
        }

        digits = ptr;
        while (isDIGIT(*ptr)) {
            if (exponent > (IV_MAX-(*ptr-'0'))/10) croak("Overflow");
            exponent = exponent * 10 + (*ptr-'0');
            ptr++;
        }
        if (negexp) exponent = -exponent;
        /* No exponent digits -> Make sure we will warn */
        if (digits == ptr) ptr = exp;
    } else exp = ptr;
    while (isSPACE(*ptr)) ptr++;
    if (exponent == 0) {
        /* Plain digit string (possibly upto . or e) */
        if (!BN_dec2bn(&big, string)) CRYPTO_CROAK("BN_dec2bn error");
    } else if (exponent < 0) {
        if (!dot) dot = exp;
        dot += exponent;
        if (dot <= string) {
            if (BN_zero(big) != 1) CRYPTO_CROAK("BN_zero error");
            return;
        }
        if (dot-string > INT_MAX-1) croak("Overflow");
        Newx(tmp, dot-string+1, char);
        Copy(string, tmp, dot-string, char);
        tmp[dot-string] = 0;
        rc = BN_dec2bn(&big, tmp);
        Safefree(tmp);
        if (!rc) CRYPTO_CROAK("BN_dec2bn error");
    } else {
        /* exponent > 0 */
        if (dot) {
            if (dot+1+exponent > exp) exponent -= exp-dot-1;
            else {
                exp = dot+1+exponent;
                exponent = 0;
            }
            if (exp-string > INT_MAX) croak("Overflow");
            Newx(tmp, exp-string, char);
            Copy(string, tmp, dot-string, char);
            Copy(dot+1, tmp+(dot-string), exp-dot-1, char);
            tmp[exp-string-1] = 0;
            rc = BN_dec2bn(&big, tmp);
            Safefree(tmp);
            if (!rc) CRYPTO_CROAK("BN_dec2bn error");
        } else if (!BN_dec2bn(&big, string)) CRYPTO_CROAK("BN_dec2bn error");
        if (exponent) big_exp10(big, exponent);
    }
    if (negative) BN_set_negative(big, 1);
    if (*ptr) NOT_A_NUMBER(sv, from, len);
}

static const char default_class[] = PACKAGE_BASE "::BigInt";
#define SV_BIGINT(sv, context) sv_bigint(aTHX_ &sv, context, 0)
#define SV_BIGINT_RESULT(sv, context)	\
	sv_bigint(aTHX_ &sv, context, default_class)
#define SV_BIGINT_CLASS(sv, context, class) sv_bigint(aTHX_ &sv, context, class)
static wec_bigint sv_bigint(pTHX_ SV **sv,
                            const char *context, const char *class) {
    SV *value;
    wec_bigint bigint, result;
    BIGNUM *big;

    value = *sv;
    bigint = TRY_C_OBJECT(value, PACKAGE_BASE "::BigInt");
    if (bigint) {
        if (!class || class == default_class) return bigint;
        NEW_CLASS(result, value, class);
        if (!BN_copy(&result->num, &bigint->num))
            CRYPTO_CROAK("BN_copy error");
#if SENSITIVE
        result->sensitive = bigint->sensitive;
#endif /* SENSITIVE */
        *sv = value;
        return result;
    }

    Newx(bigint, 1, struct wec_bigint);
#if SENSITIVE
    bigint->sensitive = 0;
#endif /* SENSITIVE */
    big = &bigint->num;
    BN_init(big);

    if (class) {
        if (class != default_class) *sv = sv_newmortal();
    } else SAVEDESTRUCTOR(free_bigint, bigint);

    if (!SvOK(value)) {
        if (ckWARN(WARN_UNINITIALIZED))
            Perl_report_uninit(aTHX_ value);
        if (!BN_zero(big)) CRYPTO_CROAK("BN_zero error");
        goto done;
    }

    /* Try to access the value as an IV/UV */
    if (SvIOK(value)) {
        BN_ULONG ival;
        if (SvUOK(value)) {
            UV uv  = SvUVX(value);
            ival = uv;
            if ((UV) ival == uv) {
                /* No overflow */
                if (!BN_set_word(big, ival))
                    CRYPTO_CROAK("BN_set_word error");
                goto done;
            }
        } else {
            IV iv = SvIVX(value);
            if (iv > 0) {
                ival = iv;
                if ((IV) ival == iv) {
                    /* No overflow */
                    if (!BN_set_word(big, ival))
                        CRYPTO_CROAK("BN_set_word error");
                    goto done;
                }
            } else {
                ival = -iv;
                if (-(IV) ival == iv) {
                    /* No overflow */
                    if (!BN_set_word(big, ival))
                        CRYPTO_CROAK("BN_set_word error");
                    BN_set_negative(big, 1);
                    goto done;
                }
            }
        }
    }

    /* Try to access the value as a small NV */
    if (SvNOK(value)) {
        NV dval;
        BN_ULONG ival;

        dval = SvNVX(value);
        if (dval >= 0) {
            if (dval < 1+(NV) BN_MASK2) {
                /* No overflow */
                ival = dval;
                if (!BN_set_word(big, ival))
                    CRYPTO_CROAK("BN_set_word error");
                goto done;
            }
        } else {
            if (-dval < 1+(NV) BN_MASK2) {
                /* No overflow */
                ival = -dval;
                if (!BN_set_word(big, ival))
                    CRYPTO_CROAK("BN_set_word error");
                BN_set_negative(big, 1);
                goto done;
            }
        }
        if (!SvPOK(value)) {
            big_from_nv(big, dval);
            goto done;
        }
    }

    big_from_pv(aTHX_ big, value, context);
  done:
    if (class) {
        sv_setref_pv(*sv, class, (void*) bigint);
        SvTAINT(*sv);
    }
    return bigint;
}

typedef struct {
    wec_bigint bigint;
    NV nval;
    BN_ULONG ival;
    int flags;
} typed_int;

/* typed_int flag values */
/* bigint entry filled in (will autodestruct) */
#define HAS_BIGINT	 0
/* val entry filled in with the absolute value of a positive number */
#define HAS_POSITIVE_INT	 1
/* val entry filled in with the absolute value of a negative number */
#define HAS_NEGATIVE_INT	 2
/* not filled in at all */
#define HAS_NOTHING	 3

#define SV_TYPEDINT(typed, value, context)	\
	sv_typed_int(aTHX_ &(typed), value, context)

/* *value may be a WEC::SSL:BigInt, IV, UV, NV or string
   returns the value in *typed as either a BN_ULONG with an external sign or
   a wec_bigint */
static void sv_typed_int(pTHX_ typed_int *typed, SV *value,
                         const char *context) {
    wec_bigint bigint;
    BIGNUM *big;

    bigint = TRY_C_OBJECT(value, PACKAGE_BASE "::BigInt");
    if (bigint) {
        typed->bigint = bigint;
        if (!RETYPE || bigint->num.top > 1) typed->flags  = HAS_BIGINT;
        else if (bigint->num.top) {
            typed->ival = bigint->num.d[0];
            typed->flags = BN_is_negative(&bigint->num) ?
                HAS_NEGATIVE_INT : HAS_POSITIVE_INT;
        } else {
            typed->ival = 0;
            typed->flags = HAS_POSITIVE_INT;
        }
        return;
    }

    if (!SvOK(value)) {
        if (ckWARN(WARN_UNINITIALIZED))
            /* Perl_warner(aTHX_ packWARN(WARN_UNINITIALIZED), PL_warn_uninit, " in ", OP_NAME(PL_op)); */
            Perl_report_uninit(aTHX_ value);
        typed->ival   = 0;
        typed->flags  = HAS_POSITIVE_INT;
        typed->bigint = (wec_bigint) &ZERO;
        return;
    }

    /* Try to access the value as an IV/UV */
    if (SvIOK(value)) {
        BN_ULONG ival;
        if (SvUOK(value)) {
            UV uv  = SvUVX(value);
            ival = uv;
            if ((UV) ival == uv) {
                /* No overflow */
                typed->ival   = ival;
                typed->flags  = HAS_POSITIVE_INT;
                typed->bigint = (wec_bigint) &ZERO;
                return;
            }
        } else {
            IV iv = SvIVX(value);
            if (iv >= 0) {
                ival = iv;
                if ((IV) ival == iv) {
                    /* No overflow */
                    typed->ival   = ival;
                    typed->flags  = HAS_POSITIVE_INT;
                    typed->bigint = (wec_bigint) &ZERO;
                    return;
                }
            } else {
                ival = -iv;
                if (-(IV) ival == iv) {
                    /* No overflow */
                    typed->ival   = ival;
                    typed->flags  = HAS_NEGATIVE_INT;
                    typed->bigint = (wec_bigint) &ZERO;
                    return;
                }
            }
        }
    }

    /* Try to access the value as a small NV */
    if (SvNOK(value)) {
        NV dval;

        dval = SvNVX(value);
        if (dval >= 0) {
            if (dval < 1+(NV) BN_MASK2) {
                /* No overflow */
                typed->ival   = dval;
                typed->flags  = HAS_POSITIVE_INT;
                typed->bigint = (wec_bigint) &ZERO;
                return;
            }
        } else {
            if (-dval < 1+(NV) BN_MASK2) {
                /* No overflow */
                typed->ival   = -dval;
                typed->flags  = HAS_NEGATIVE_INT;
                typed->bigint = (wec_bigint) &ZERO;
                return;
            }
        }
    }

    Newx(bigint, 1, struct wec_bigint);
#if SENSITIVE
    bigint->sensitive = 0;
#endif /* SENSITIVE */
    big = &bigint->num;
    BN_init(big);

    SAVEDESTRUCTOR(free_bigint, bigint);

    if (SvNOK(value) && !SvPOK(value)) big_from_nv(big, SvNVX(value));
    else big_from_pv(aTHX_ big, value, context);
    typed->bigint = bigint;
    typed->flags  = HAS_BIGINT;
    return;
}

#define SV_SET_FROM_BIGINT(sv, num, flags)		\
	sv_set_from_BIGINT(aTHX_ sv, num, flags)

#define ABSOLUTE	1
#define	INTEGER		2
/* Important: cannot croak unless flags contains INTEGER */
static void sv_set_from_BIGINT(pTHX_ SV *sv, BIGNUM *num, int flags) {
    int bytes, left;
    UV uv;
    NV nv;

    bytes = BN_num_bytes(num);
    if (bytes == 0) {
        sv_setiv(sv, 0);
        return;
    }
    if (bytes*8 <= sizeof(UV)*CHAR_BIT) {
        bytes = (bytes-1)/BN_BYTES;
        uv = num->d[bytes];
        while (bytes) {
            uv <<= BN_BITS2;
            uv += num->d[--bytes];
        }
        if (!(flags & ABSOLUTE) && BN_is_negative(num))
            if (uv > 1+(UV) IV_MAX)
                if (flags & INTEGER) croak("value out of range");
                else sv_setnv(sv, -(NV) uv);
            else
                /* This might overflow, but the negate should fix it */
                sv_setiv(sv, -(IV)uv);
        else sv_setuv(sv, uv);
        return;
    }
    if (flags & INTEGER) croak("value out of range");
    if (bytes*8 <= sizeof(NV)*CHAR_BIT) {
        bytes = (bytes-1)/BN_BYTES;
        nv = num->d[bytes];
        while (bytes) {
            nv *= 1+(NV)BN_MASK2;
            nv += num->d[--bytes];
        }
    } else {
        bytes = (bytes-1)/BN_BYTES;
        nv = num->d[bytes];
        left = sizeof(NV)*CHAR_BIT;
        while (bytes && left > 0) {
            nv *= 1+(NV)BN_MASK2;
            nv += num->d[--bytes];
            left -= BN_BITS2;
        }
        if (bytes) nv *= Perl_pow(1+(NV)BN_MASK2, bytes);
    }
    if (!(flags & ABSOLUTE) && BN_is_negative(num)) nv = -nv;
    sv_setnv(sv, nv);
}

/* Helper function for the bitwise operators */
/* Caller must guarantee there is at least one U8 != 0 in [start, end[ */
static void sign_fixup(U8 *start, U8 *ptr) {
    /* Carry part */
    do {
        --ptr;
        *ptr = 1+~*ptr;
    } while(*ptr == 0);
    /* complement part */
    while (ptr > start) {
        --ptr;
        *ptr = ~*ptr;
    }
}

#define GET_SENSITIVE(sensitive)	\
	(sensitive ? get_sensitive(aTHX_ sensitive) : 0)

static bool get_sensitive(pTHX_ SV *sensitive) {
    wec_bigint bigsensitive;
    bool need_magic;

    /* Try to guess when SvTRUE does no mg_get */
    need_magic = SvPOK(sensitive) || SvIOK(sensitive) || SvNOK(sensitive);
    if (SvTRUE(sensitive)) return 1;
#if SENSITIVE
    if (need_magic) SvGETMAGIC(sensitive);
    /* Should also accept the other types with a sensitivity flag */
    bigsensitive = TRY_C_OBJECT(sensitive, PACKAGE_BASE "::BigInt");
    if (bigsensitive && bigsensitive->sensitive)
        croak("Turning sensitivity off using a sensitive value");
#endif /* SENSITIVE */
    return 0;
}

typedef struct perl_cb {
    BN_GENCB gen_cb;
    IV period;
    PerlInterpreter *my_perl;
    SV *callback, *phase, *iteration, *err;
    bool died;
} PERL_CB;

/* Support perl functions as callback for slow BIGNUM operation */
static int do_bn_callback(int phase, int iteration, BN_GENCB *closure) {
    PERL_CB *perl_cb = closure->arg;
    if (phase == 1 && iteration == -1) phase = iteration = 0;
    if (perl_cb->period && iteration % perl_cb->period) return 1;
    {
        dTHXa(perl_cb->my_perl);
        I32 count;
        dSP;

        sv_setiv(perl_cb->phase, phase);
        sv_setiv(perl_cb->iteration, iteration);

        PUSHMARK(SP);
        XPUSHs(perl_cb->phase);
        XPUSHs(perl_cb->iteration);
        PUTBACK;
        count = call_sv(perl_cb->callback, G_VOID | G_EVAL);
        SPAGAIN;
        if (count) {
            if (count < 0)
                sv_setpvf(perl_cb->err, "Forced void context callback succeeded in returning %d values. This is impossible", (int) count);
            else SP -= count;
        }
        PUTBACK;
        perl_cb->died = SvTRUE(perl_cb->err);
        return !perl_cb->died;
    }
}

static BN_GENCB *perl_callback(pTHX_ PERL_CB *perl_cb, SV *callback, IV period) {
    if (!callback) return NULL;
    BN_GENCB_set(&perl_cb->gen_cb, do_bn_callback, perl_cb);
    perl_cb->my_perl	= aTHX+0;
    perl_cb->callback	= callback;
    perl_cb->phase	= sv_newmortal();
    perl_cb->iteration	= sv_newmortal();
    perl_cb->err	= get_sv("@", TRUE);
    perl_cb->died	= 0;
    perl_cb->period	= period;
    return &perl_cb->gen_cb;
}

MODULE = WEC::SSL::BigInt		PACKAGE = WEC::SSL::BigInt
PROTOTYPES: ENABLE

void
new(SV *class, SV *from)
  PREINIT:
    const char *class_name;
  PPCODE:
    TAINT_NOT;
    class_name = C_CLASS(class);
    SV_BIGINT_CLASS(from, "from", class_name);
    PUSHs(from);

void
rand_prime(const char *class, ...)
  PREINIT:
    I32 i;
    const char *name;
    SV *value, *object, *callback;
    STRLEN len;
    wec_bigint result, modulus, remainder;
    IV callback_period;
    int rc, safe, bits;
#if SENSITIVE
    int sensitive;
    bool sens;
#endif /* SENSITIVE */
    PERL_CB perl_cb;
    BN_GENCB *gen_cb;
  PPCODE:
    TAINT_RAND;
    if (items % 2 == 0) croak("Odd number of arguments");
    bits = -1;
    callback_period = 0;
#if SENSITIVE
    sens = 0;
    sensitive = -1;
#endif /* SENSITIVE */
    safe = -1;
    modulus = remainder = NULL;
    callback = NULL;
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 1) switch(name[0]) {
          case 'b': case 'B':
            if (LOW_EQ(name, len, "bits") ||
                LOW_EQ(name, len, "bit_length")) {
                if (bits >= 0) croak("Multiple bits arguments");
                bits = GET_INT_SENSITIVE(value, sens, "bits");
                if (bits < 2) {
                    if (bits < 0) croak("Negative number of bits");
                    croak("There are no %"IVdf" bit primes", (IV) bits);
                }
                goto OK;
            }
            break;
          case 'c': case 'C':
            if (LOW_EQ(name, len, "callback_period")) {
                bool old_tainted;

                if (callback_period)
                    croak("Multiple callback_period arguments");

                /* The callback_period normally doesn't influence the result,
                   only the displaying, so don't propagate the taint */
                old_tainted = PL_tainted;
                callback_period = GET_INT(value, "callback_period");
                PL_tainted = old_tainted;
                if (callback_period <= 0) {
                    if (callback_period == 0) croak("Zero callback_period");
                    croak("Negative callback_period");
                }
                goto OK;
            }
            if (LOW_EQ(name, len, "callback")) {
                if (callback) croak("Multiple callback arguments");
                callback = value;
                SvREFCNT_inc(callback);
                sv_2mortal(callback);
                goto OK;
            }
            break;
          case 'm': case 'M':
            if (LOW_EQ(name, len, "modulus") ||
                LOW_EQ(name, len, "mod") ||
                LOW_EQ(name, len, "m")) {
                if (modulus) croak("Multiple modulus arguments");
                modulus = SV_BIGINT(value, "modulus");
                /* Internals of generate don't work if modulus is negative */
                if (BN_is_negative(&modulus->num)) croak("Negative modulus");
#if SENSITIVE
                sens |= modulus->sensitive;
#endif /* SENSITIVE */
                goto OK;
            }
            break;
          case 'r': case 'R':
            if (LOW_EQ(name, len, "remainder") ||
                LOW_EQ(name, len, "r")) {
                if (remainder) croak("Multiple remainder arguments");
                remainder = SV_BIGINT(value, "remainder");
                /* Negative remainders work just fine */
#if SENSITIVE
                sens |= remainder->sensitive;
#endif /* SENSITIVE */
                goto OK;
            }
            break;
          case 's': case 'S':
            if (LOW_EQ(name, len, "safe")) {
                if (safe >= 0) croak("Multiple safe arguments");
                safe = SvTRUE(value) ? 1 : 0;
                goto OK;
            }
#if SENSITIVE
            if (LOW_EQ(name, len, "sensitive")) {
                if (sensitive >= 0) croak("Multiple sensitive arguments");
                sensitive = GET_SENSITIVE(value);
                goto OK;
            }
#endif /* SENSITIVE */
            break;
        }
        croak("Unknown option '%"SVf"'", ST(i));
      OK:;
    }
    if (remainder && !modulus) croak("Remainder without modulus");
    if (callback_period && !callback)
        croak("Callback_period without callback");
    if (bits < 0) croak("No bits argument");
    if (safe < 0) safe = 0;
    if (!callback_period) callback_period = 1;
    gen_cb = callback ?
        perl_callback(aTHX_ &perl_cb, callback, callback_period) : NULL;
    NEW_CLASS(result, object, class);
#if SENSITIVE
    result->sensitive = sensitive >= 0 ? sensitive : sens;
#endif /* SENSITIVE */
    PUSHs(object);
    PUTBACK;
    rc = BN_generate_prime_ex(&result->num, bits, safe,
                              &modulus->num, &remainder->num, gen_cb);
    SPAGAIN;
    if (gen_cb && perl_cb.died) croak(Nullch);
    if (!rc) CRYPTO_CROAK("BN_generate_prime error");
    rc = BN_num_bits(&result->num);
    if (rc != bits) {
        if (rc > bits) croak("Prime too big (openssl flaw)");
        else           croak("Prime too small (openssl flaw)");
    }

void
is_prime(SV *arg, ...)
  PREINIT:
    I32 i;
    wec_bigint bigint;
    IV checks, callback_period;
    NV nval;
    int rc, trial_divisions;
    SV *callback, *value;
    BN_CTX *ctx;
    const char *name;
    STRLEN len;
    PERL_CB perl_cb;
    BN_GENCB *gen_cb;
  PPCODE:
    if (items % 2 == 0) croak("Odd number of arguments");
    checks = -1;
    callback_period = 0;
    trial_divisions = -1;
    callback = NULL;
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 4) switch(name[0]) {
          case 'c': case 'C':
            if (LOW_EQ(name, len, "checks")) {
                if (checks >= 0) croak("Multiple checks arguments");
                SvGETMAGIC(value);
                if (SvOK(value)) {
                    nval = SvNV(value);
                    if (nval < 1) {
                        if (nval <= -1) croak("Negative number of checks");
                        croak("Zero checks");
                    }
                    if (nval >= (NV) INT_MAX+1) croak("Checks out of range");
                    checks = nval;
                } else checks = 0;
                goto OK;
            }
            if (LOW_EQ(name, len, "callback_period")) {
                if (callback_period)
                    croak("Multiple callback_period arguments");
                nval = SvNV(value);
                if (nval < 1) {
                    if (nval <= -1) croak("Negative callback_period");
                    croak("Zero callback_period");
                }
                if (nval >= (NV) INT_MAX+1)
                    croak("Callback_period out of range");
                callback_period = nval;
                goto OK;
            }
            if (LOW_EQ(name, len, "callback")) {
                if (callback) croak("Multiple callback arguments");
                callback = value;
                SvREFCNT_inc(callback);
                sv_2mortal(callback);
                goto OK;
            }
            break;
          case 't': case 'T':
            if (LOW_EQ(name, len, "trial_divisions")) {
                if (trial_divisions >= 0)
                    croak("Multiple trial_divisions arguments");
                trial_divisions = SvTRUE(value) ? 1 : 0;
                goto OK;
            }
            break;
        }
        croak("Unknown option '%"SVf"'", ST(i));
      OK:;
    }
    if (callback_period && !callback)
        croak("Callback_period without callback");
    if (checks < 0) checks = BN_prime_checks;
    if (trial_divisions < 0) trial_divisions = 0;
    bigint = SV_BIGINT(arg, "arg");
    /* Bug workaround */
    if (BN_is_word(&bigint->num, 2)) XPUSHs(&PL_sv_yes);
    else {
        if (!callback_period) callback_period = 1;
        gen_cb = callback ?
            perl_callback(aTHX_ &perl_cb, callback, callback_period) : NULL;
        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        PUTBACK;
        rc = BN_is_prime_fasttest_ex(&bigint->num, (int) checks, ctx,
                                     trial_divisions, gen_cb);
        SPAGAIN;
        BN_CTX_free(ctx);
        if (gen_cb && perl_cb.died) croak(Nullch);
        if (rc < 0) CRYPTO_CROAK("BN_is_prime_fasttest_ex error");
        XPUSHs(rc ? &PL_sv_yes : &PL_sv_no);
    }

void
ZERO(const char *class=NULL)
  PREINIT:
    SV *object;
    wec_bigint result;
  PPCODE:
    TAINT_NOT;
    NEW_CLASS(result, object, class ? class : PACKAGE_BASE "::BigInt");
    if (BN_zero(&result->num) != 1) CRYPTO_CROAK("BN_zero error");
    PUSHs(object);

void
ONE(const char *class=NULL)
  PREINIT:
    SV *object;
    wec_bigint result;
  PPCODE:
    TAINT_NOT;
    NEW_CLASS(result, object, class ? class : PACKAGE_BASE "::BigInt");
    if (BN_one(&result->num) != 1) CRYPTO_CROAK("BN_one error");
    PUSHs(object);

void
MAX_WORD(const char *class=NULL)
  PREINIT:
    SV *object;
    wec_bigint result;
  PPCODE:
    TAINT_NOT;
    NEW_CLASS(result, object, class ? class : PACKAGE_BASE "::BigInt");
    if (!BN_set_word(&result->num, BN_MASK2))
        CRYPTO_CROAK("BN_set_word error");
    XPUSHs(object);

void
PERL_MAX_WORD()
  PPCODE:
    TAINT_NOT;
    XPUSHs(newSVuv(UV_MAX <= BN_MASK2 ? UV_MAX : BN_MASK2));

void
from_decimal(const char *class, SV *decimal_string, SV *sensitive=NULL)
  ALIAS:
    WEC::SSL::BigInt::from_hex = 1
  PREINIT:
    wec_bigint bigint;
    SV *object;
    const char *string;
    BIGNUM *big;
    bool is_sensitive;
  PPCODE:
    TAINT_NOT;
    string = ix ?
        C_HEX(decimal_string, "Hex string") :
        C_DECIMAL(decimal_string, "Decimal string");
    is_sensitive = GET_SENSITIVE(sensitive);
    NEW_CLASS(bigint, object, class);
#if SENSITIVE
    bigint->sensitive = is_sensitive;
#endif /* SENSITIVE */
    big = &bigint->num;
    if (ix) {
        if (!BN_hex2bn(&big, string))
            CRYPTO_CROAK("Could not convert hexadecimal string");
    } else {
        if (!BN_dec2bn(&big, string))
            CRYPTO_CROAK("Could not convert decimal string");
    }
    PUSHs(object);

SV *
to_decimal(SV *arg, SV *dummy=NULL, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::to_HEX = 1
    WEC::SSL::BigInt::to_hex = 2
  PREINIT:
    wec_bigint bigint;
    char *string;
  CODE:
    TAINT_NOT;
    bigint = SV_BIGINT(arg, "arg");
    if (ix) {
        bool mode = SvTRUE(dummy);
        if (items > 2) croak("Usage: arg->%s(even=NULL)", GvNAME(CvGV(cv)));
        string = BN_bn2hex(&bigint->num);
        if (!string) CRYPTO_CROAK("Could not convert BIGNUM to hex");
        if (string[0] == '0' && string[1] == 0) {
            /* Special case: num == 0 */
            RETVAL = mode ? newSVpvn("00", 2) : newSVpvn("0", 1);
            goto done;
        }
        if (ix == 2) {
            char *ptr;
            for (ptr = string; *ptr; ptr++) *ptr = toLOWER(*ptr);
            if (string[0] == '-' && string[1] == '0' && !dummy) {
                string[1] = '-';
                RETVAL = newSVpvn(string+1, ptr-(string+1));
            } else if (string[0] == '0' && !dummy) {
                RETVAL = newSVpvn(string+1, ptr-(string+1));
            } else RETVAL = newSVpvn(string, ptr-string);
            goto done;
        }
        if (string[0] == '-' && string[1] == '0' && !dummy) {
            string[1] = '-';
            RETVAL = newSVpv(string+1, 0);
            goto done;
        }
        if (string[0] == '0' && !dummy) {
            RETVAL = newSVpv(string+1, 0);
            goto done;
        }
    } else {
        string = BN_bn2dec(&bigint->num);
        if (!string) CRYPTO_CROAK("BN_bn2dec error");
    }
    RETVAL = newSVpv(string, 0);
  done:;
#if SENSITIVE
    if (bigint->sensitive) Zero(string, SvCUR(RETVAL), char);
#endif /* SENSITIVE */
    OPENSSL_free(string);
  OUTPUT:
    RETVAL

void
from_bin(const char *class, SV *bin_string, SV *sensitive = NULL)
  ALIAS:
    WEC::SSL::BigInt::from_mpi = 1
  PREINIT:
    wec_bigint bigint;
    SV *object;
    const char *string;
    STRLEN len;
    bool is_sensitive;
  PPCODE:
    TAINT_NOT;
    string = SV_BYTES(bin_string, len);
    if (len > INT_MAX) croak("string length out of range");
    is_sensitive = GET_SENSITIVE(sensitive);
    NEW_CLASS(bigint, object, class);
#if SENSITIVE
    bigint->sensitive = is_sensitive;
#endif /* SENSITIVE */
    if (ix) {
        if (!BN_mpi2bn(string, (int) len, &bigint->num))
            CRYPTO_CROAK("Could not convert mpi string");
    } else {
        if (!BN_bin2bn(string, (int) len, &bigint->num))
            CRYPTO_CROAK("Could not convert bin string");
    }
    PUSHs(object);

SV *
abs_to_bin(SV *arg)
  ALIAS:
    WEC::SSL::BigInt::to_bin = 1
    WEC::SSL::BigInt::to_mpi = 2
  PREINIT:
    wec_bigint bigint;
    unsigned char *string;
    int len;
    STRLEN dummy_len;
  CODE:
    TAINT_NOT;
    bigint = SV_BIGINT(arg, "arg");
    if (ix == 1 && BN_is_negative(&bigint->num))
        croak("No bin representation for negative numbers");
    len = ix == 2 ? BN_bn2mpi(&bigint->num, NULL) : BN_num_bytes(&bigint->num);
    RETVAL = newSV(len);
    sv_setpvn(RETVAL, "", 0);
    string = SvPV(RETVAL, dummy_len);

    if (ix == 2) BN_bn2mpi(&bigint->num, string);
    else         BN_bn2bin(&bigint->num, string);

    string[len] = 0;
    SvCUR_set(RETVAL, len);
  OUTPUT:
    RETVAL

void
is_one(SV *arg, SV *dummy=NULL, SV *how=NULL)
  PREINIT:
    typed_int typed;
  PPCODE:
    TAINT_NOT;
    SV_TYPEDINT(typed, arg, "arg");
    if (typed.flags == HAS_BIGINT)
        arg = BN_is_one(&typed.bigint->num) ? &PL_sv_yes : &PL_sv_no;
    else
        arg = typed.ival == 1 && typed.flags == HAS_POSITIVE_INT ? &PL_sv_yes : &PL_sv_no;
    if (PL_tainting && PL_tainted) {
        /* The &PL_sv_yes : &PL_sv_no constants are always untainted */
        arg = newSVsv(arg);
        SvTAINTED_on(arg);
    }
    PUSHs(arg);

void
is_odd(SV *arg, SV *dummy=NULL, SV *how=NULL)
  PREINIT:
    typed_int typed;
  PPCODE:
    TAINT_NOT;
    SV_TYPEDINT(typed, arg, "arg");
    if (typed.flags == HAS_BIGINT)
        arg = BN_is_odd(&typed.bigint->num) ? &PL_sv_yes : &PL_sv_no;
    else
        arg = typed.ival % 2 ? &PL_sv_yes : &PL_sv_no;
    if (PL_tainting && PL_tainted) {
        /* The &PL_sv_yes : &PL_sv_no constants are always untainted */
        arg = newSVsv(arg);
        SvTAINTED_on(arg);
    }
    PUSHs(arg);

void
is_even(SV *arg, SV *dummy=NULL, SV *how=NULL)
  PREINIT:
    typed_int typed;
  PPCODE:
    TAINT_NOT;
    SV_TYPEDINT(typed, arg, "arg");
    if (typed.flags == HAS_BIGINT)
        arg = BN_is_odd(&typed.bigint->num) ? &PL_sv_no : &PL_sv_yes;
    else
        arg = typed.ival % 2 ? &PL_sv_no : &PL_sv_yes;
    if (PL_tainting && PL_tainted) {
        /* The &PL_sv_yes : &PL_sv_no constants are always untainted */
        arg = newSVsv(arg);
        SvTAINTED_on(arg);
    }
    PUSHs(arg);

void
is_zero(SV *arg, SV *dummy=NULL, SV *how=NULL)
  PREINIT:
    typed_int typed;
    bool old_tainted;
  PPCODE:
    /* Save taint since we overload this class.
       That means an SvTRUE can otherwise zero PL_tainted */
    old_tainted = PL_tainted;
    TAINT_NOT;
    SV_TYPEDINT(typed, arg, "arg");
    if (typed.flags == HAS_BIGINT)
        arg = BN_is_zero(&typed.bigint->num) ? &PL_sv_yes : &PL_sv_no;
    else
        arg = typed.ival ? &PL_sv_no : &PL_sv_yes;
    if (PL_tainting && PL_tainted) {
        /* The &PL_sv_yes : &PL_sv_no constants are always untainted */
        arg = newSVsv(arg);
        SvTAINTED_on(arg);
    }
    PUSHs(arg);
    PL_tainted = old_tainted;

void
is_non_zero(SV *arg, SV *dummy=NULL, SV *how=NULL)
  PREINIT:
    typed_int typed;
    bool old_tainted;
  PPCODE:
    /* Save taint since we overload this class.
       That means an SvTRUE can otherwise zero PL_tainted */
    old_tainted = PL_tainted;
    TAINT_NOT;
    SV_TYPEDINT(typed, arg, "arg");
    if (typed.flags == HAS_BIGINT)
        arg = BN_is_zero(&typed.bigint->num) ? &PL_sv_no : &PL_sv_yes;
    else
        arg = typed.ival ? &PL_sv_yes : &PL_sv_no;
    if (PL_tainting && PL_tainted) {
        /* The &PL_sv_yes : &PL_sv_no constants are always untainted */
        arg = newSVsv(arg);
        SvTAINTED_on(arg);
    }
    PUSHs(arg);
    PL_tainted = old_tainted;

void
eq(SV *arg1, SV *arg2, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::ne = 1
  PREINIT:
    wec_bigint a;
    typed_int typed;
    bool retval;
  PPCODE:
    a = SV_BIGINT(arg1, "arg1");
    SV_TYPEDINT(typed, arg2, "arg2");
    switch(typed.flags) {
      case HAS_POSITIVE_INT:
        retval = BN_is_word(&a->num, typed.ival);
        break;
      case HAS_NEGATIVE_INT:
        retval = BN_is_negative(&a->num) &&
            BN_abs_is_word(&a->num, typed.ival);
        break;
      default:
        retval = !BN_cmp(&a->num, &typed.bigint->num);
        break;
    }
    if (ix) retval = !retval;
    PUSHs(retval ? &PL_sv_yes : &PL_sv_no);

void
cmp(SV *arg1, SV *arg2, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::lt = 2
    WEC::SSL::BigInt::le = 3
    WEC::SSL::BigInt::gt = 4
    WEC::SSL::BigInt::ge = 5
  PREINIT:
    wec_bigint a;
    BIGNUM *num;
    typed_int typed;
    int cmp;
    SV *object;
  PPCODE:
    TAINT_NOT;
    a = SV_BIGINT(arg1, "arg1");
    num = &a->num;
    SV_TYPEDINT(typed, arg2, "arg2");
    switch(typed.flags) {
      case HAS_POSITIVE_INT:
        if (BN_is_negative(num)) cmp = -1;
        else switch(num->top) {
          case 0:
            cmp = typed.ival ? - 1 : 0;
            break;
          case 1:
            cmp =
                num->d[0] < typed.ival ? -1 :
                num->d[0] > typed.ival ?  1 :
                0;
            break;
          default:
            cmp = 1;
            break;
        }
        break;
      case HAS_NEGATIVE_INT:
        if (BN_is_negative(num))
            if (num->top == 1)
                cmp =
                    num->d[0] < typed.ival ?  1 :
                    num->d[0] > typed.ival ? -1 :
                    0;
            else cmp = -1;
        else cmp = 1;
        break;
      default:
        cmp = BN_cmp(num, &typed.bigint->num);
        break;
    }
    if (SvTRUE(how)) cmp = -cmp;
    switch(ix) {
      case 2: object = cmp <  0 ? &PL_sv_yes : &PL_sv_no; break;
      case 3: object = cmp <= 0 ? &PL_sv_yes : &PL_sv_no; break;
      case 4: object = cmp >  0 ? &PL_sv_yes : &PL_sv_no; break;
      case 5: object = cmp >= 0 ? &PL_sv_yes : &PL_sv_no; break;
      default:
        object = how && !SvOK(how) ? arg1 : sv_newmortal();
        sv_setiv(object, cmp);
        break;
    }
    PUSHs(object);

void
abs_cmp(SV *arg1, SV *arg2, SV *how=NULL)
  PREINIT:
    wec_bigint a;
    BIGNUM *num;
    typed_int typed;
    int cmp;
    SV *object;
  PPCODE:
    TAINT_NOT;
    a = SV_BIGINT(arg1, "arg1");
    num = &a->num;
    SV_TYPEDINT(typed, arg2, "arg2");
    if (typed.flags == HAS_BIGINT) cmp = BN_ucmp(num, &typed.bigint->num);
    else switch(num->top) {
      case 0:
        cmp = typed.ival ? - 1 : 0;
        break;
      case 1:
        cmp =
            num->d[0] < typed.ival ? -1 :
            num->d[0] > typed.ival ?  1 :
            0;
        break;
      default:
        cmp = 1;
        break;
    }
    if (SvTRUE(how)) cmp = -cmp;
    object = how && !SvOK(how) ? arg1 : sv_newmortal();
    sv_setiv(object, cmp);
    PUSHs(object);

void
lshift1(SV *from, SV *dummy=NULL, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::rshift1 = 1
  PREINIT:
    wec_bigint value, result;
  PPCODE:
    TAINT_NOT;
    if (how && (SvGETMAGIC(how), !SvOK(how)))
        result = value = SV_BIGINT_RESULT(from, "argument");
    else {
        value = SV_BIGINT(from, "argument");
        NEW_BIGINT(result, from);
#if SENSITIVE
        result->sensitive = value->sensitive;
#endif /* SENSITIVE */
    }
    if (ix) {
        int rc;
        if (BN_is_negative(&value->num) && BN_is_odd(&value->num)) {
            /* Fixup value */
            if (!BN_add_word(&value->num, 1))
                CRYPTO_CROAK("BN_add_word error");
            /* Do real shift */
            rc = BN_rshift1(&result->num, &value->num);
            /* repair value */
            if (BN_is_zero(&value->num)) {
                /* Work around bug in BN_sub_word */
                if (!BN_one(&value->num)) CRYPTO_CROAK("BN_one error");
                BN_set_negative(&value->num, 1);
            } else if (!BN_sub_word(&value->num, 1))
                CRYPTO_CROAK("BN_sub_word error");
            if (rc && result != value) {
                /* Repair result */
                if (BN_is_zero(&result->num)) {
                    /* Work around bug in BN_sub_word */
                    if (!BN_one(&result->num)) CRYPTO_CROAK("BN_one error");
                    BN_set_negative(&result->num, 1);
                } else if (!BN_sub_word(&result->num, 1))
                    CRYPTO_CROAK("BN_sub_word error");
            }
        } else rc = BN_rshift1(&result->num, &value->num);
        if (!rc) CRYPTO_CROAK("BN_rshift1 error");
    } else {
        if (!BN_lshift1(&result->num, &value->num))
            CRYPTO_CROAK("BN_lshift1 error");
    }
    PUSHs(from);

void
square(SV *from, SV *dummy=NULL, SV *how=NULL)
  PREINIT:
    wec_bigint bigint, result;
    int rc;
    BN_CTX *ctx;
  PPCODE:
    TAINT_NOT;
    if (how && (SvGETMAGIC(how), !SvOK(how))) {
        bigint = SV_BIGINT_RESULT(from, "argument");

        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        rc = BN_sqr(&bigint->num, &bigint->num, ctx);
    } else {
        bigint = SV_BIGINT(from, "argument");
        NEW_BIGINT(result, from);
#if SENSITIVE
        result->sensitive = bigint->sensitive;
#endif /* SENSITIVE */
        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        rc = BN_sqr(&result->num, &bigint->num, ctx);
    }
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK("BN_sqr error");
    PUSHs(from);

void
bit(SV *arg, SV *bit_nr, SV *value=NULL)
  ALIAS:
    WEC::SSL::BigInt::abs_bit = 1
  PREINIT:
    wec_bigint result, bigsensitive;
    typed_int typed;
    BN_ULONG bits;
    SV *object;
    int rc;
    const char *error;
    bool bit, fixup, need_magic;
  PPCODE:
    TAINT_NOT;
    SV_TYPEDINT(typed, bit_nr, "bit_nr");
    if (typed.flags == HAS_BIGINT) {
        if (typed.bigint->num.top) {
            if (typed.bigint->num.top > 1) croak("Bitnumber too large");
            typed.ival = typed.bigint->num.d[0];
            if (BN_is_negative(&typed.bigint->num))
                typed.flags = HAS_NEGATIVE_INT;
        } else typed.ival = 0;
    }
    if (typed.ival > INT_MAX) croak("Bitnumber too large");

    if (value) result = SV_BIGINT_RESULT(arg, "arg");
    else result = SV_BIGINT(arg, "arg");

    fixup = !ix && BN_is_negative(&result->num);
    if (fixup && !BN_add_word(&result->num, 1))
        CRYPTO_CROAK("BN_add_word error");

    error = NULL;
    if (typed.flags == HAS_NEGATIVE_INT) {
        bits = BN_num_bits(&result->num);
        if (typed.ival > bits) {
            error = "Bitnumber too negative";
            goto do_fix;
        }
        typed.ival = bits - typed.ival;
    }
    if (GIMME_V != G_VOID) {
        object = sv_newmortal();
        PUSHs(object);
        rc = BN_is_bit_set(&result->num, (int) typed.ival);
        if (fixup) sv_setiv(object, !rc);
        else sv_setiv(object, rc);
    }
    if (value) {
        need_magic = SvPOK(value) || SvIOK(value) || SvNOK(value);
        bit = SvTRUE(value);
        if (bit != fixup) {
            rc = BN_set_bit(&result->num, (int) typed.ival);
            if (!rc) {
                error = "set_bit error";
                goto do_fix;
            }
        } else if (typed.flags == HAS_NEGATIVE_INT ||
                   typed.ival < BN_num_bits(&result->num)) {
            rc = BN_clear_bit(&result->num, (int) typed.ival);
            if (!rc) {
                error = "clear_bit error";
                goto do_fix;
            }
        }
#if SENSITIVE
        result->sensitive |= typed.bigint->sensitive;
        if (!result->sensitive) {
            if (need_magic) SvGETMAGIC(value);
            /* Also accept the other types with a sensitivity flag ? */
            bigsensitive = TRY_C_OBJECT(value, PACKAGE_BASE "::BigInt");
            if (bigsensitive) result->sensitive = bigsensitive->sensitive;
        }
#endif /* SENSITIVE */
    }
  do_fix:
    if (fixup) {
        if (BN_is_zero(&result->num)) {
            if (!BN_one(&result->num)) CRYPTO_CROAK("BN_one error");
            BN_set_negative(&result->num, 1);
        } else {
            /* Just in case we we lost the negative flag in the add_word */
            BN_set_negative(&result->num, 1);
            if (!BN_sub_word(&result->num, 1))
                CRYPTO_CROAK("BN_sub_word error");
        }
    }
    if (error) CRYPTO_CROAK(error);
    if (value && PL_tainting && PL_tainted) {
        sv_taint(arg);
        sv_taint(SvRV(arg));
    }

void
mask_bits(SV *arg, SV *nr_bits, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::abs_mask_bits = 1
  PREINIT:
    wec_bigint result, a;
    typed_int typed;
    const char *error;
    bool fixup;
  PPCODE:
    TAINT_NOT;
    if (SvTRUE(how)) {
        SV *tmp = arg;
        arg = nr_bits;
        nr_bits = tmp;
    }

    SV_TYPEDINT(typed, nr_bits, "nr_bits");
    if (typed.flags == HAS_BIGINT) {
        if (typed.bigint->num.top) {
            if (typed.bigint->num.top > 1) croak("Bits too large");
            typed.ival = typed.bigint->num.d[0];
            if (BN_is_negative(&typed.bigint->num))
                typed.flags = HAS_NEGATIVE_INT;
        } else typed.ival = 0;
    }
    if (typed.ival > INT_MAX) croak("Bits too large");

    if (how && !SvOK(how)) {
        /* inplace */
        result = a = SV_BIGINT_RESULT(arg, "arg");
    } else {
        a = SV_BIGINT(arg, "arg");
        NEW_BIGINT(result, arg);
#if SENSITIVE
        result->sensitive = a->sensitive;
#endif /* SENSITIVE */
    }
    PUSHs(arg);

    fixup = !ix && BN_is_negative(&a->num);
    if (fixup && !BN_add_word(&a->num, 1)) CRYPTO_CROAK("BN_add_word error");

    error = NULL;
    if (typed.flags == HAS_NEGATIVE_INT) {
        int bits = BN_num_bits(&a->num);
        if (typed.ival > bits) {
            error = "Bits too negative";
            goto do_fix;
        }
        bits -= typed.ival;
        if (!BN_rshift(&result->num, &a->num, bits )) {
            error = "Could not rshift";
            goto do_fix;
        }
    } else if (typed.ival < BN_num_bits(&a->num)) {
        if (a != result) {
            if (typed.ival && !BN_set_bit(&result->num, (int) typed.ival -1)) {
                error = "Could not set_bit";
                goto do_fix;
            }
            Copy(a->num.d, result->num.d, result->num.top, BN_ULONG);
            result->num.neg = a->num.neg;
            if ((int) typed.ival % BN_BITS2 &&
                !BN_mask_bits(&result->num, (int) typed.ival)) {
                error = "Could not mask_bits";
                goto do_fix;
            }
        } else if (!BN_mask_bits(&result->num, (int) typed.ival)) {
            error = "Could not mask_bits";
            goto do_fix;
        }
    } else if (a != result && !BN_copy(&result->num, &a->num)) {
        error = "Could not copy";
        goto do_fix;
    }
#if SENSITIVE
    result->sensitive |= typed.bigint->sensitive;
#endif /* SENSITIVE */
    if (fixup) {
        int i, top;
        top = ((int) typed.ival + BN_BITS2-1) / BN_BITS2;
        if (typed.ival && !bn_wexpand(&result->num, top)) {
            error = "Could not set_bit";
            goto do_fix;
        }
        for (i=0; i< top; i++) result->num.d[i] = ~result->num.d[i] & BN_MASK2;
        result->num.top = top;
        /* typed.ival % BN_BITS2 is to work around a bug in BN_mask_bits
           (error for the case of exactly matching bits) */
        if ((int) typed.ival % BN_BITS2 &&
            !BN_mask_bits(&result->num, (int) typed.ival)) {
            error = "Could not mask_bits";
            goto do_fix;
        }
        BN_set_negative(&result->num, 0);
    }
    if (a != result)
  do_fix:
    if (fixup) {
        if (BN_is_zero(&a->num)) {
            if (!BN_one(&a->num)) CRYPTO_CROAK("BN_one error");
            BN_set_negative(&a->num, 1);
        } else if (!BN_sub_word(&a->num, 1)) CRYPTO_CROAK("BN_sub_word error");
    }
    if (error) CRYPTO_CROAK(error);

int
bit_length(SV *from)
  ALIAS:
    WEC::SSL::BigInt::byte_length = 1
  PREINIT:
    typed_int typed;
  CODE:
    TAINT_NOT;
    SV_TYPEDINT(typed, from, "argument");
    RETVAL = typed.flags == HAS_BIGINT ?
        BN_num_bits(&typed.bigint->num) :
        BN_num_bits_word(typed.ival);
    if (ix) RETVAL = (RETVAL+7) / 8;
  OUTPUT:
    RETVAL

void
copy_sign(SV *arg1, SV *arg2, SV *how=NULL)
  PREINIT:
    wec_bigint result, a;
    typed_int typed;
  PPCODE:
    TAINT_NOT;
    if (SvTRUE(how)) {
        SV *tmp = arg1;
        arg1 = arg2;
        arg2 = tmp;
    }
    SV_TYPEDINT(typed, arg2, "arg2");
    /* No SvGETMAGIC because SvTRUE already did that if needed */
    if (how && !SvOK(how) && typed.flags != HAS_BIGINT) {
        /* $a -= $val */
        result = a = SV_BIGINT_RESULT(arg1, "arg1");
    } else {
        a = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
#if SENSITIVE
        result->sensitive = a->sensitive;
#endif /* SENSITIVE */
    }
    switch(typed.flags) {
      case HAS_POSITIVE_INT:
        if (typed.ival == 0) {
            if (!BN_zero(&result->num)) croak("Could not zero bignum");
            break;
        }
        if (a != result && !BN_copy(&result->num, &a->num))
            croak("Could not copy bignum");
        BN_set_negative(&result->num, 0);
        break;
      case HAS_NEGATIVE_INT:
        if (a != result && !BN_copy(&result->num, &a->num))
            croak("Could not copy bignum");
        BN_set_negative(&result->num, 1);
        break;
      case HAS_BIGINT:
        if (BN_is_zero(&typed.bigint->num)) {
            if (!BN_zero(&result->num)) croak("Could not zero bignum");
            break;
        }
        if (a != result && !BN_copy(&result->num, &a->num))
            croak("Could not copy bignum");
        BN_set_negative(&result->num, BN_is_negative(&typed.bigint->num));
        break;
    }
#if SENSITIVE
    result->sensitive |= typed.bigint->sensitive;
#endif /* SENSITIVE */
    XPUSHs(arg1);

int
sign(const struct wec_bigint *from, SV *dummy=NULL, SV *how=NULL)
  CODE:
    /* TAINT_NOT; */
    RETVAL = BN_is_negative(&from->num) ? -1 : BN_is_zero(&from->num) ? 0 : 1;
  OUTPUT:
    RETVAL

void
lshift(SV *arg1, SV *arg2, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::rshift = 1
  PREINIT:
    int rc;
    int distance;
    wec_bigint value, result;
    bool sensitive;
  PPCODE:
    TAINT_NOT;
    if (SvTRUE(how)) {
        SV *tmp = arg1;
        arg1 = arg2;
        arg2 = tmp;
    }
    sensitive = 0;
    distance = GET_INT_SENSITIVE(arg2, sensitive, "shift distance");

    if (how && !SvOK(how)) result = value = SV_BIGINT_RESULT(arg1, "arg1");
    else {
        value = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
#if SENSITIVE
        result->sensitive = value->sensitive;
#endif /* SENSITIVE */
    }

    if (ix) distance = -distance;
    if (distance >= 0)
        rc = distance == 1 ?
            BN_lshift1(&result->num, &value->num) :
            BN_lshift(&result->num, &value->num, (int) distance);
    else if (BN_is_negative(&value->num) &&
             (distance != -1 || BN_is_odd(&value->num))) {
        /* Fixup value */
        if (!BN_add_word(&value->num, 1)) CRYPTO_CROAK("BN_add_word error");
        /* Do real shift */
        rc = BN_rshift(&result->num, &value->num, -(int) distance);
        /* repair value */
        if (BN_is_zero(&value->num)) {
            /* Work around bug in BN_sub_word */
            if (!BN_one(&value->num)) CRYPTO_CROAK("BN_one error");
            BN_set_negative(&value->num, 1);
        } else if (!BN_sub_word(&value->num, 1))
            CRYPTO_CROAK("BN_sub_word error");
        if (rc == 1 && result != value) {
            /* Repair result */
            if (BN_is_zero(&result->num)) {
                /* Work around bug in BN_sub_word */
                if (!BN_one(&result->num)) CRYPTO_CROAK("BN_one error");
                BN_set_negative(&result->num, 1);
            } else if (!BN_sub_word(&result->num, 1))
                CRYPTO_CROAK("BN_sub_word error");
        }
    } else rc = distance == -1 ?
        BN_rshift1(&result->num, &value->num) :
        BN_rshift(&result->num, &value->num, -(int) distance);
    if (rc != 1) CRYPTO_CROAK("Shift error");
#if SENSITIVE
    result->sensitive |= sensitive;
#endif /* SENSITIVE */
    PUSHs(arg1);

void
clear(SV *arg)
  PREINIT:
    SV *bigint;
    IV address;
    wec_bigint result;
  PPCODE:
    SvGETMAGIC(arg);
    bigint = C_SV(arg, PACKAGE_BASE "::BigInt", "arg");
    address = SvIV(bigint);
    if (!address) croak("arg object has a NULL pointer");
    result = INT2PTR(wec_bigint, address);
    BN_clear(&result->num);
#if SENSITIVE
    result->sensitive = 0;
#endif /* SENSITIVE */
    if (PL_tainting) {
        sv_untaint(bigint);
        sv_untaint(arg);
    }

void
sensitive(SV *arg, SV *sensitive=NULL)
  PREINIT:
    wec_bigint bigint;
  PPCODE:
#if SENSITIVE
    bigint = C_OBJECT(arg, PACKAGE_BASE "::BigInt", "arg");
    PUSHs(bigint->sensitive ? &PL_sv_yes : &PL_sv_no);
    if (sensitive) bigint->sensitive = GET_SENSITIVE(sensitive);
#else  /* SENSITIVE */
    croak("Sensitivity not supported");
#endif /* SENSITIVE */

void
taint(SV *arg, SV *taint=NULL)
  PPCODE:
    REF_TAINTED(arg, taint, PACKAGE_BASE "::BigInt", "arg");

void
copy(SV *arg, SV *dummy=NULL, SV *how=NULL)
  PREINIT:
    typed_int typed;
    wec_bigint result;
    SV *object;
  PPCODE:
    TAINT_NOT;
    SV_TYPEDINT(typed, arg, "arg");
    NEW_BIGINT(result, object);
#if SENSITIVE
    result->sensitive = typed.bigint->sensitive;
#endif /* SENSITIVE */
    switch(typed.flags) {
      case HAS_POSITIVE_INT:
        if (!BN_set_word(&result->num, typed.ival))
            CRYPTO_CROAK("BN_set_word error");
        break;
      case HAS_NEGATIVE_INT:
        if (!BN_set_word(&result->num, typed.ival))
            CRYPTO_CROAK("BN_set_word error");
        BN_set_negative(&result->num, 1);
        break;
      case HAS_BIGINT:
        if (!BN_copy(&result->num, &typed.bigint->num))
            CRYPTO_CROAK("BN_copy error");
        break;
    }
    XPUSHs(object);

void
add(SV *arg1, SV *arg2, SV *how=NULL)
  PREINIT:
    wec_bigint result, a;
    const struct wec_bigint *b;
    typed_int typed;
  PPCODE:
    TAINT_NOT;
    if (arg1 == arg2) {
        typed.flags = HAS_NOTHING;
        b = &ZERO;
    } else {
        SV_TYPEDINT(typed, arg2, "arg2");
        b = typed.bigint;
    }

    if (how && (SvGETMAGIC(how), !SvOK(how))) {
        /* $a += $val */
        result = a = SV_BIGINT_RESULT(arg1, "arg1");
    } else {
        a = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
#if SENSITIVE
        result->sensitive = a->sensitive;
#endif /* SENSITIVE */
    }

    switch(typed.flags) {
      case HAS_POSITIVE_INT:
        if (a != result && !BN_copy(&result->num, &a->num))
            CRYPTO_CROAK("BN_copy error");
        if (!BN_add_word(&result->num, typed.ival))
            CRYPTO_CROAK("BN_add_word error");
        break;
      case HAS_NEGATIVE_INT:
        if (BN_is_zero(&a->num)) {
            /* Work around a bug in BN_sub_word */
            if (!BN_set_word(&result->num, typed.ival))
                CRYPTO_CROAK("BN_set_word error");
            BN_set_negative(&result->num, 1);
        } else {
            if (a != result && !BN_copy(&result->num, &a->num))
                CRYPTO_CROAK("BN_copy error");
            if (!BN_sub_word(&result->num, typed.ival))
                CRYPTO_CROAK("BN_sub_word error");
        }
        break;
      case HAS_BIGINT:
        if (a != b) {
            if (!BN_add(&result->num, &a->num, &b->num))
                CRYPTO_CROAK("BN_add error");
            break;
        }
        /* fall through */
      default:
        if (!BN_lshift1(&result->num, &a->num))
            CRYPTO_CROAK("BN_lshift1 error");
        break;
    }
#if SENSITIVE
    result->sensitive |= b->sensitive;
#endif /* SENSITIVE */
    PUSHs(arg1);

void
subtract(SV *arg1, SV *arg2, SV *how=NULL)
  PREINIT:
    wec_bigint result, a;
    const struct wec_bigint *b;
    bool reverse;
    typed_int typed;
  PPCODE:
    TAINT_NOT;
    if (arg1 == arg2) {
        typed.flags = HAS_NOTHING;
        b = &ZERO;
    } else {
        SV_TYPEDINT(typed, arg2, "arg2");
        b = typed.bigint;
    }

    reverse = SvTRUE(how);
    /* No SvGETMAGIC because SvTRUE already did that if needed */
    /* docs give no guarantee that result may be shared with a or b */
    if (how && !SvOK(how) && typed.flags != HAS_BIGINT) {
        /* $a -= $val */
        result = a = SV_BIGINT_RESULT(arg1, "arg1");
    } else {
        a = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
#if SENSITIVE
        result->sensitive = a->sensitive;
#endif /* SENSITIVE */
    }

    switch(typed.flags) {
      case HAS_POSITIVE_INT:
        if (BN_is_zero(&a->num)) {
            /* Work around a bug in BN_sub_word */
            if (!BN_set_word(&result->num, typed.ival))
                CRYPTO_CROAK("BN_set_word error");
            if (!reverse) BN_set_negative(&result->num, 1);
        } else {
            if (a != result && !BN_copy(&result->num, &a->num))
                CRYPTO_CROAK("BN_copy error");
            if (!BN_sub_word(&result->num, typed.ival))
                CRYPTO_CROAK("BN_sub_word error");
            if (reverse)
                BN_set_negative(&result->num, !BN_is_negative(&result->num));
        }
        break;
      case HAS_NEGATIVE_INT:
        if (a != result && !BN_copy(&result->num, &a->num))
            CRYPTO_CROAK("BN_copy error");
        if (!BN_add_word(&result->num, typed.ival))
            CRYPTO_CROAK("BN_add_word error");
        if (reverse)
            BN_set_negative(&result->num, !BN_is_negative(&result->num));
        break;
      case HAS_BIGINT:
        if (a != b) {
            int rc = reverse ?
                BN_sub(&result->num, &b->num, &a->num) :
                BN_sub(&result->num, &a->num, &b->num);
            if (!rc) CRYPTO_CROAK("BN_sub error");
            break;
        }
        /* fall through */
      default:
        if (!BN_zero(&result->num)) CRYPTO_CROAK("BN_zero error");
        break;
    }
#if SENSITIVE
    result->sensitive |= b->sensitive;
#endif /* SENSITIVE */
    PUSHs(arg1);

void
multiply(SV *arg1, SV *arg2, SV *how=NULL)
  PREINIT:
    wec_bigint result, a;
    const struct wec_bigint *b;
    BN_CTX *ctx;
    typed_int typed;
    int rc;
  PPCODE:
    TAINT_NOT;
    if (arg1 == arg2) {
        typed.flags = HAS_NOTHING;
        b = &ZERO;
    } else {
        SV_TYPEDINT(typed, arg2, "arg2");
        b = typed.bigint;
    }

    if (how && (SvGETMAGIC(how), !SvOK(how))) {
        /* $a *= $val */
        result = a = SV_BIGINT_RESULT(arg1, "arg1");
    } else {
        a = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
#if SENSITIVE
        result->sensitive = a->sensitive;
#endif /* SENSITIVE */
    }

    switch(typed.flags) {
      case HAS_POSITIVE_INT:
      case HAS_NEGATIVE_INT:
        if (a != result && !BN_copy(&result->num, &a->num))
            CRYPTO_CROAK("BN_copy error");
        if (!BN_mul_word(&result->num, typed.ival))
            CRYPTO_CROAK("BN_mul_word error");
        if (typed.flags == HAS_NEGATIVE_INT)
            BN_set_negative(&result->num, !BN_is_negative(&result->num));
        break;
      default:
        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        if (typed.flags == HAS_BIGINT) {
            if (a != b) {
                rc = BN_mul(&result->num, &a->num, &b->num, ctx);
                BN_CTX_free(ctx);
                if (!rc) CRYPTO_CROAK("BN_mul error");
                break;
            }
        }
        rc = BN_sqr(&result->num, &a->num, ctx);
        BN_CTX_free(ctx);
        if (!rc) CRYPTO_CROAK("BN_sqr error");
        break;
    }
#if SENSITIVE
    result->sensitive |= b->sensitive;
#endif /* SENSITIVE */
    PUSHs(arg1);

void
divide(SV *arg1, SV *arg2, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::perl_divide   = 1
    WEC::SSL::BigInt::quotient      = 2
    WEC::SSL::BigInt::remainder     = 3
    WEC::SSL::BigInt::abs_remainder = 4
    WEC::SSL::BigInt::modulo        = 5
  PREINIT:
    BIGNUM rb;
    wec_bigint result, r, a, b;
    SV *remainder;
    BN_CTX *ctx;
    BN_ULONG rest;
    typed_int typed;
    int rc;
  PPCODE:
    TAINT_NOT;
    if (SvTRUE(how)) {
        /* reverse */
        SV *tmp = arg1;
        arg1 = arg2;
        arg2 = tmp;
    }

    if (arg1 == arg2) {
        typed.flags = HAS_NOTHING;
        /* Take care that b indeed doesn't get changed! */
        b = (wec_bigint) &ZERO;
    } else {
        SV_TYPEDINT(typed, arg2, "arg2");
        b = typed.bigint;
    }

    if (ix <= 1) {
        U32 gimme = GIMME_V;
        if (gimme == G_VOID) {
            if (typed.flags == HAS_POSITIVE_INT) {
                if (typed.ival == 0) croak("div by zero");
            } else if (typed.flags == HAS_BIGINT) {
                if (BN_is_zero(&typed.bigint->num)) croak("div by zero");
            }
            XSRETURN_EMPTY;
        }
        if (gimme == G_SCALAR) {
            /* fall back to quotient */
            ix = 2;
        }
    }

    /* No SvGETMAGIC because SvTRUE already did that if needed */
    /* docs give no guarantee that result may be shared with a or b */
    if (how && !SvOK(how) && typed.flags != HAS_BIGINT) {
        /* $a /= $val */
        result = a = SV_BIGINT_RESULT(arg1, "arg1");
    } else {
        a = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
#if SENSITIVE
        result->sensitive = a->sensitive;
#endif /* SENSITIVE */
    }
    PUSHs(arg1);

    switch(typed.flags) {
      case HAS_POSITIVE_INT:
        if (typed.ival == 0) croak("div by zero");
        /* fall through */
      case HAS_NEGATIVE_INT:
        if (ix >= 3) {
            rest = BN_mod_word(&a->num, typed.ival);
            if (rest == BN_MASK2) CRYPTO_CROAK("BN_mod_word error");
#if SENSITIVE
            result->sensitive |= b->sensitive;
#endif /* SENSITIVE */
            switch(ix) {
              case 3:	/* remainder */
                /* Take care to check the sign of a before setting result
                   since they may be the same */
                if (rest && BN_is_negative(&a->num)) {
                    if (!BN_set_word(&result->num, rest))
                        CRYPTO_CROAK("BN_set_word error");
                    BN_set_negative(&result->num, 1);
                } else if (!BN_set_word(&result->num, rest))
                    CRYPTO_CROAK("BN_set_word error");
                break;
              case 4:	/* abs_remainder */
                if (rest && BN_is_negative(&a->num)) rest = typed.ival-rest;
                if (!BN_set_word(&result->num, rest))
                    CRYPTO_CROAK("BN_set_word error");
                break;
              default:	/* modulo */
                if (rest && BN_is_negative(&a->num) != (typed.flags == HAS_NEGATIVE_INT)) rest = typed.ival-rest;
                if (!BN_set_word(&result->num, rest))
                    CRYPTO_CROAK("BN_set_word error");
                if (typed.flags == HAS_NEGATIVE_INT)
                    BN_set_negative(&result->num, 1);
                break;
            }
        } else {
            int negate = BN_is_negative(&a->num);
            if (a != result && !BN_copy(&result->num, &a->num))
                CRYPTO_CROAK("BN_copy error");
            rest = BN_div_word(&result->num, typed.ival);
            if (rest == BN_MASK2) CRYPTO_CROAK("BN_div_word error");
#if SENSITIVE
            result->sensitive |= b->sensitive;
#endif /* SENSITIVE */
            if (typed.flags == HAS_NEGATIVE_INT)
                BN_set_negative(&result->num, !negate);
            if (ix == 0) {	/* divide */
                NEW_BIGINT(r, remainder);
                PUSHs(remainder);
#if SENSITIVE
                r->sensitive = result->sensitive;
#endif /* SENSITIVE */
                if (!BN_set_word(&r->num, rest))
                    CRYPTO_CROAK("BN_set_word error");
                if (negate) BN_set_negative(&r->num, 1);
            } else if (ix == 1) {	/* perl_divide */
                remainder = sv_newmortal();
                PUSHs(remainder);
#if BN_BITS2 < UVSIZE*CHAR_BIT
                if (negate) sv_setiv(remainder, -(IV) rest);
                else        sv_setuv(remainder, (UV) rest);
#else
                if (negate)
                    if (rest <= 1+(UV)IV_MAX) sv_setiv(remainder, -(IV) rest);
                    else sv_setnv(remainder, -(NV) rest);
                else
                    if (rest <= UV_MAX) sv_setuv(remainder, (UV) rest);
                    else sv_setnv(remainder, (NV) rest);
#endif
            }
        }
        break;
      case HAS_BIGINT:
        if (a != b) {
            ctx = BN_CTX_new();
            if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
            switch(ix) {
              case 3:	/* remainder */
                rc = BN_mod(&result->num, &a->num, &b->num, ctx);
                break;
              case 4:	/* abs_remainder */
                rc = BN_nnmod(&result->num, &a->num, &b->num, ctx);
                break;
              case 5:	/* modulo */
                if (BN_is_negative(&b->num)) {
                    if (BN_is_zero(&a->num)) rc = BN_zero(&result->num);
                    else {
                        BN_set_negative(&a->num, !BN_is_negative(&a->num));
                        BN_set_negative(&b->num, 0);
                        rc = BN_nnmod(&result->num, &a->num, &b->num, ctx);
                        BN_set_negative(&a->num, !BN_is_negative(&a->num));
                        BN_set_negative(&b->num, 1);
                        if (rc) BN_set_negative(&result->num, 1);
                    }
                } else rc = BN_nnmod(&result->num, &a->num, &b->num, ctx);
                break;
              case 0:	/* divide */
                NEW_BIGINT(r, remainder);
                PUSHs(remainder);
                rc = BN_div(&result->num, &r->num, &a->num, &b->num, ctx);
#if SENSITIVE
                if (rc) r->sensitive = result->sensitive | b->sensitive;
#endif /* SENSITIVE */
                break;
              case 1:	/* perl_divide */
                remainder = sv_newmortal();
                PUSHs(remainder);
                BN_init(&rb);
                rc = BN_div(&result->num, &rb, &a->num, &b->num, ctx);
                if (rc) {
                    SV_SET_FROM_BIGINT(remainder, &rb, 0);
#if SENSITIVE
                    if (a->sensitive || b->sensitive) BN_clear(&rb);
#endif /* SENSITIVE */
                    BN_free(&rb);
                }
                break;
              default:	/* quotient */
                rc = BN_div(&result->num, NULL, &a->num, &b->num, ctx);
                break;
            }
            BN_CTX_free(ctx);
            if (!rc) CRYPTO_CROAK("Divide error");
#if SENSITIVE
            result->sensitive |= b->sensitive;
#endif /* SENSITIVE */
            break;
        }
        /* fall through */
      default:
        if (BN_is_zero(&a->num)) croak("div by zero");
        switch(ix) {
          case 0:	/* divide */
            if (!BN_one(&result->num)) CRYPTO_CROAK("BN_one error");
            NEW_BIGINT(r, remainder);
            PUSHs(remainder);
#if SENSITIVE
            r->sensitive = result->sensitive;
#endif /* SENSITIVE */
            if (!BN_zero(&r->num)) CRYPTO_CROAK("BN_zero error");
            break;
          case 1:	/* perl_divide */
            if (!BN_one(&result->num)) CRYPTO_CROAK("BN_one error");
            remainder = sv_newmortal();
            PUSHs(remainder);
            sv_setiv(remainder, 0);
            break;
          case 2:	/* quotient */
            if (!BN_one(&result->num)) CRYPTO_CROAK("BN_one error");
            break;
          default:
            if (!BN_zero(&result->num)) CRYPTO_CROAK("BN_zero error");
            break;
        }
        break;
    }

void
perl_modulo(SV *arg1, SV *arg2, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::perl_remainder     = 1
    WEC::SSL::BigInt::perl_abs_remainder = 2
  PREINIT:
    BIGNUM rb;
    wec_bigint a, b;
    BN_CTX *ctx;
    BN_ULONG rest;
    typed_int typed;
    int rc, negative;
  PPCODE:
    TAINT_NOT;
    if (SvTRUE(how)) {
        /* reverse */
        SV *tmp = arg1;
        arg1 = arg2;
        arg2 = tmp;
    }

    if (arg1 == arg2) {
        typed.flags = HAS_NOTHING;
    } else {
        SV_TYPEDINT(typed, arg2, "arg2");
    }

    /* No SvGETMAGIC because SvTRUE already did that if needed */
    if (how && !SvOK(how)) a = SV_BIGINT_RESULT(arg1, "arg1");
    else {
        a = SV_BIGINT(arg1, "arg1");
        arg1 = sv_newmortal();
    }
    PUSHs(arg1);

    switch(typed.flags) {
      case HAS_POSITIVE_INT:
        if (typed.ival == 0) croak("div by zero");
        /* fall through */
      case HAS_NEGATIVE_INT:
        rest = BN_mod_word(&a->num, typed.ival);
        if (rest == BN_MASK2) CRYPTO_CROAK("BN_mod_word error");
        switch(ix) {
          case 1:	/* remainder */
            negative = rest && BN_is_negative(&a->num);
            break;
          case 2:	/* abs_remainder */
            if (rest && BN_is_negative(&a->num)) rest = typed.ival-rest;
            negative = 0;
            break;
          default:	/* modulo */
            if (rest && BN_is_negative(&a->num) != (typed.flags == HAS_NEGATIVE_INT)) rest = typed.ival-rest;
            negative = typed.flags == HAS_NEGATIVE_INT;
            break;
        }
#if BN_BITS2 < UVSIZE*CHAR_BIT
        if (negative) sv_setiv(arg1, -(IV)rest);
        else          sv_setuv(arg1, (UV) rest);
#else
        if (negative)
            if (rest <= 1+(UV) IV_MAX) sv_setiv(arg1, -(IV)rest);
            else sv_setnv(arg1, -(NV)rest);
        else
            if (rest <= UV_MAX) sv_setuv(arg1, (UV) rest);
            else sv_setnv(arg1, (NV) rest);
#endif
        break;
      case HAS_BIGINT:
        b = typed.bigint;
        if (a != b) {
            ctx = BN_CTX_new();
            if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
            BN_init(&rb);
            switch(ix) {
              case 1:	/* remainder */
                rc = BN_mod(&rb, &a->num, &b->num, ctx);
                break;
              case 2:	/* abs_remainder */
                rc = BN_nnmod(&rb, &a->num, &b->num, ctx);
                break;
              default:	/* modulo */
                if (BN_is_negative(&b->num)) {
                    if (BN_is_zero(&a->num)) rc = BN_zero(&rb);
                    else {
                        BN_set_negative(&a->num, !BN_is_negative(&a->num));
                        BN_set_negative(&b->num, 0);
                        rc = BN_nnmod(&rb, &a->num, &b->num, ctx);
                        BN_set_negative(&a->num, !BN_is_negative(&a->num));
                        BN_set_negative(&b->num, 1);
                        if (rc) BN_set_negative(&rb, 1);
                    }
                } else rc = BN_nnmod(&rb, &a->num, &b->num, ctx);
                break;
            }
            SV_SET_FROM_BIGINT(arg1, &rb, 0);
#if SENSITIVE
            if (a->sensitive || b->sensitive) BN_clear(&rb);
#endif /* SENSITIVE */
            BN_free(&rb);
            BN_CTX_free(ctx);
            if (!rc) CRYPTO_CROAK("Divide error");
            break;
        }
        /* fall through */
      default:
        if (BN_is_zero(&a->num)) croak("div by zero");
        sv_setiv(arg1, 0);
        break;
    }

void
pow(SV *arg1, SV *arg2, SV *how=NULL)
  PREINIT:
    wec_bigint result, a, b;
    BIGNUM v, *r;
    BN_CTX *ctx;
    typed_int typed;
    int rc, bits;
    BN_ULONG exp, rev_exp;
    bool needs_v;
  PPCODE:
    TAINT_NOT;
    if (SvTRUE(how)) {
        /* reverse */
        SV *tmp = arg1;
        arg1 = arg2;
        arg2 = tmp;
    }
    SV_TYPEDINT(typed, arg2, "arg2");
    b = typed.bigint;

    /* No SvGETMAGIC because SvTRUE already did that if needed */
    /* docs give no guarantee that result may be shared with a or b */
    if (how && !SvOK(how) && typed.flags != HAS_BIGINT) {
        /* $a /= $val */
        result = a = SV_BIGINT_RESULT(arg1, "arg1");
    } else {
        a = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
#if SENSITIVE
        result->sensitive = a->sensitive;
#endif /* SENSITIVE */
    }

    switch(typed.flags) {
      case HAS_POSITIVE_INT:
#if SENSITIVE
        result->sensitive |= b->sensitive;
#endif /* SENSITIVE */
        r = &result->num;
        exp = typed.ival;
        if (exp == 0) {
            if (BN_one(r) != 1) CRYPTO_CROAK("BN_one error");
            break;
        }
        if (result != a && !BN_copy(r, &a->num))
            CRYPTO_CROAK("BN_copy error");
        for (rev_exp = 0, bits = 0; exp != 1; exp >>=1, bits++)
            rev_exp = (rev_exp << 1) + (exp & 1);
        if (bits == 0) break;
        needs_v = rev_exp != 0;
        if (needs_v) {
            BN_init(&v);
            if (!BN_copy(&v, &a->num)) CRYPTO_CROAK("BN_copy error");
        }

        ctx = BN_CTX_new();
        if (!ctx) {
            if (needs_v) {
#if SENSITIVE
                if (a->sensitive) BN_clear(&v);
#endif /* SENSITIVE */
                BN_free(&v);
            }
            CRYPTO_CROAK("BN_CTX_new error");
        }
        do {
            if (!BN_sqr(r, r, ctx)) {
                BN_CTX_free(ctx);
                if (needs_v) {
#if SENSITIVE
                    if (a->sensitive) BN_clear(&v);
#endif /* SENSITIVE */
                    BN_free(&v);
                }
                CRYPTO_CROAK("BN_sqr error");
            }
            if ((rev_exp & 1) && !BN_mul(r, r, &v, ctx)) {
                BN_CTX_free(ctx);
                if (needs_v) {
#if SENSITIVE
                    if (a->sensitive) BN_clear(&v);
#endif /* SENSITIVE */
                    BN_free(&v);
                }
                CRYPTO_CROAK("BN_mul error");
            }
            rev_exp >>= 1;
        } while (--bits);
        BN_CTX_free(ctx);
        if (needs_v) {
#if SENSITIVE
            if (a->sensitive) BN_clear(&v);
#endif /* SENSITIVE */
            BN_free(&v);
        }
        break;
      case HAS_NEGATIVE_INT:
        croak("Negative exponent not supported");
        break;
      default:
        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        if (BN_is_negative(&b->num)) {
            BN_CTX_free(ctx);
            croak("Negative exponent not supported");
        }
        rc = BN_exp(&result->num, &a->num, &b->num, ctx);
        BN_CTX_free(ctx);
        if (!rc) CRYPTO_CROAK("BN_exp error");
#if SENSITIVE
        result->sensitive |= b->sensitive;
#endif /* SENSITIVE */
        break;
    }
    PUSHs(arg1);

void
gcd(SV *arg1, SV *arg2, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::mod_inverse = 1
  PREINIT:
    wec_bigint result, a, b;
    BN_CTX *ctx;
    int rc;
    bool reverse;
  PPCODE:
    TAINT_NOT;
    b = SV_BIGINT(arg2, "arg2");

    reverse = SvTRUE(how);
    /* No SvGETMAGIC since SvTRUE already did that if needed */
    if (how && !SvOK(how)) {
        /* $a gcd= $val */
        result = a = SV_BIGINT_RESULT(arg1, "arg1");
    } else {
        a = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
    }
    ctx = BN_CTX_new();
    if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
    if (ix == 1) {
        rc = (reverse ?
              BN_mod_inverse(&result->num, &b->num, &a->num, ctx) :
              BN_mod_inverse(&result->num, &a->num, &b->num, ctx)) != NULL;
    } else {
        rc = reverse ?
            BN_gcd(&result->num, &b->num, &a->num, ctx) :
            BN_gcd(&result->num, &a->num, &b->num, ctx);
        if (rc && BN_is_zero(&result->num)) {
            BN_CTX_free(ctx);
            croak("gcd(0, 0) is undefined");
        }
    }
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK(ix ? "BN_mod_inverse error" : "BN_gcd error");
#if SENSITIVE
    result->sensitive = a->sensitive | b->sensitive;
#endif /* SENSITIVE */
    PUSHs(arg1);

void
mod_multiply(SV *arg1, SV *arg2, SV *arg3)
  ALIAS:
    WEC::SSL::BigInt::mod_add = 1
    WEC::SSL::BigInt::mod_subtract = 2
    WEC::SSL::BigInt::mod_pow = 3
  PREINIT:
    wec_bigint result, a, b, m;
    SV *object;
    BN_CTX *ctx;
    int rc;
  PPCODE:
    TAINT_NOT;
    /* docs give no guarantee that result may be shared with a, b or m */
    b = SV_BIGINT(arg2, "arg2");
    if (ix == 3 && BN_is_negative(&b->num))
        croak("Negative exponent not supported");
    a = arg1 == arg2 ? b : SV_BIGINT(arg1, "arg1");
    m = SV_BIGINT(arg3, "arg3");
    NEW_BIGINT(result, object);
#if SENSITIVE
    result->sensitive = a->sensitive | b->sensitive | m->sensitive;
#endif /* SENSITIVE */
    switch(ix) {
      case 1:	/* mod_add */
        if (a == b) {
            BIGNUM d;

            BN_init(&d);
            if (!BN_lshift1(&d, &a->num)) {
#if SENSITIVE
                if (a->sensitive) BN_clear(&d);
#endif /* SENSITIVE */
                BN_free(&d);
                CRYPTO_CROAK("BN_lshift1 error");
            }
            ctx = BN_CTX_new();
            if (!ctx) {
#if SENSITIVE
                if (a->sensitive) BN_clear(&d);
#endif /* SENSITIVE */
                BN_free(&d);
                CRYPTO_CROAK("BN_CTX_new error");
            }
            rc = BN_nnmod(&result->num, &d, &m->num, ctx);
            BN_CTX_free(ctx);
#if SENSITIVE
            if (a->sensitive) BN_clear(&d);
#endif /* SENSITIVE */
            BN_free(&d);
            if (!rc) CRYPTO_CROAK("BN_mod error");
            break;
        }
        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        rc = BN_mod_add(&result->num, &a->num, &b->num, &m->num, ctx);
        BN_CTX_free(ctx);
        if (!rc) CRYPTO_CROAK("BN_mod_add error");
        break;
      case 2:	/* mod_subtract */
        if (a == b && !BN_is_zero(&m->num)) {
            if (!BN_zero(&result->num)) CRYPTO_CROAK("BN_zero error");
            break;
        }
        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        rc = BN_mod_sub(&result->num, &a->num, &b->num, &m->num, ctx);
        BN_CTX_free(ctx);
        if (!rc) CRYPTO_CROAK("BN_mod_sub error");
        break;
      case 3:	/* mod_pow */
        if (BN_is_zero(&b->num)) {
            /* Bug workaround */
            if (BN_is_zero(&m->num)) croak("div by zero");
            if (BN_abs_is_word(&m->num, 1)) {
                if (!BN_zero(&result->num)) CRYPTO_CROAK("BN_zero error");
                break;
            }
            if (!BN_one(&result->num)) CRYPTO_CROAK("BN_one error");
            break;
        }
        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        rc = BN_mod_exp(&result->num, &a->num, &b->num, &m->num, ctx);
        BN_CTX_free(ctx);
        if (!rc) CRYPTO_CROAK("BN_mod_mul error");
        break;
      default:	/* mod_multiply */
        ctx = BN_CTX_new();
        if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
        if (a == b) {
            rc = BN_mod_sqr(&result->num, &a->num, &m->num, ctx);
            BN_CTX_free(ctx);
            if (!rc) CRYPTO_CROAK("BN_mod_sqr error");
            break;
        }
        rc = BN_mod_mul(&result->num, &a->num, &b->num, &m->num, ctx);
        BN_CTX_free(ctx);
        if (!rc) CRYPTO_CROAK("BN_mod_mul error");
        break;
    }
    PUSHs(object);

void
mod_square(SV *arg1, SV *arg2, SV *how = NULL)
  PREINIT:
    wec_bigint result, a, m;
    SV *object;
    BN_CTX *ctx;
    int rc;
  PPCODE:
    TAINT_NOT;
    if (SvTRUE(how)) {
        SV *tmp = arg1;
        arg1 = arg2;
        arg2 = tmp;
    }
    /* docs give no guarantee that result may be shared with a or m */
    a = SV_BIGINT(arg1, "arg1");
    m = SV_BIGINT(arg2, "arg2");
    NEW_BIGINT(result, object);
    ctx = BN_CTX_new();
    if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
#if SENSITIVE
    result->sensitive = a->sensitive | m->sensitive;
#endif /* SENSITIVE */
    rc = BN_mod_sqr(&result->num, &a->num, &m->num, ctx);
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK("BN_mod_sqr error");
    PUSHs(object);

void
negate(SV *from, SV *dummy=NULL, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::complement = 1
  PREINIT:
    wec_bigint bigint, result;
  PPCODE:
    TAINT_NOT;
    if (how && (SvGETMAGIC(how), !SvOK(how)))
        result = SV_BIGINT_RESULT(from, "argument");
    else {
        bigint = SV_BIGINT(from, "argument");
        NEW_BIGINT(result, from);
        if (!BN_copy(&result->num, &bigint->num))
            CRYPTO_CROAK("BN_copy error");
#if SENSITIVE
        result->sensitive = bigint->sensitive;
#endif /* SENSITIVE */
    }
    if (BN_is_zero(&result->num)) {
        /* work around bugs for 0 */
        if (ix) {
            /* Construct -1, but BN_sub_word on zero is buggy */
            if (BN_one(&result->num) != 1) CRYPTO_CROAK("BN_one error");
            BN_set_negative(&result->num, 1);
        }
    } else {
        BN_set_negative(&result->num, !BN_is_negative(&result->num));
        if (ix) {
            if (!BN_sub_word(&result->num, 1))
                CRYPTO_CROAK("BN_sub_word error");
        }
    }
    PUSHs(from);

void
int(SV *arg, SV *dummy=NULL, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::abs  = 1
    WEC::SSL::BigInt::inc  = 2
    WEC::SSL::BigInt::dec  = 3
    WEC::SSL::BigInt::inc_mutate  = 4
    WEC::SSL::BigInt::dec_mutate  = 5
  PREINIT:
    typed_int typed;
    wec_bigint result;
  PPCODE:
    TAINT_NOT;
    if (ix >= 4 || (how && (SvGETMAGIC(how), !SvOK(how)))) {
        /* $a ++ */
        result = SV_BIGINT_RESULT(arg, "arg");
    } else {
        SV_TYPEDINT(typed, arg, "arg");
        NEW_BIGINT(result, arg);
        switch(typed.flags) {
          case HAS_POSITIVE_INT:
            if (!BN_set_word(&result->num, typed.ival))
                CRYPTO_CROAK("BN_set_word error");
            break;
          case HAS_NEGATIVE_INT:
            if (!BN_set_word(&result->num, typed.ival))
                CRYPTO_CROAK("BN_set_word error");
            BN_set_negative(&result->num, 1);
            break;
          default:
            if (!BN_copy(&result->num, &typed.bigint->num))
                CRYPTO_CROAK("BN_copy error");
            break;
        }
#if SENSITIVE
        result->sensitive = typed.bigint->sensitive;
#endif /* SENSITIVE */
    }

    switch(ix) {
      case 1:
        BN_set_negative(&result->num, 0);
        break;
      case 2:
      case 4:
        if (!BN_add_word(&result->num, 1)) CRYPTO_CROAK("BN_add_word error");
        break;
      case 3:
      case 5:
        if (BN_is_zero(&result->num)) {
            if (BN_one(&result->num) != 1) CRYPTO_CROAK("BN_one error");
            BN_set_negative(&result->num, 1);
        } else if (!BN_sub_word(&result->num, 1))
            CRYPTO_CROAK("BN_sub_word error");
        break;
      default:
        break;
    }
    PUSHs(arg);

void
perl_int(SV *arg, SV *dummy=NULL, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::to_integer     = 1
    WEC::SSL::BigInt::perl_abs       = 2
    WEC::SSL::BigInt::abs_to_integer = 3
  PREINIT:
    typed_int typed;
    SV *object;
    int flags;
  PPCODE:
    TAINT_NOT;
    SV_TYPEDINT(typed, arg, "arg");

    if (how && (SvGETMAGIC(how), !SvOK(how))) object = arg;
    else object = sv_newmortal();

    switch(typed.flags) {
      case HAS_NEGATIVE_INT:
        if (ix <= 1) {
#if BN_BITS2 < UVSIZE*CHAR_BIT
            sv_setiv(object, -(IV) typed.ival);
#else
            if (typed.ival <= 1+(UV) IV_MAX)
                /* This might overflow, but the negate should fix it */
                sv_setiv(object, -(IV) typed.ival);
            else if (ix & 1) croak("value out of range");
            else sv_setnv(object, - (NV) typed.ival);
#endif
            break;
        }
        /* fall through */
      case HAS_POSITIVE_INT:
#if BN_BITS2 < UVSIZE*CHAR_BIT
        sv_setuv(object, (UV) typed.ival);
#else
        if (typed.ival <= UV_MAX) sv_setuv(object, (UV) typed.ival);
        else if (ix & 1) croak("value out of range");
        else sv_setnv(object, (NV) typed.ival);
#endif
        break;
      default:
        flags = 0;
        if (ix >= 2) flags |= ABSOLUTE;
        if (ix & 1)  flags |= INTEGER;
        SV_SET_FROM_BIGINT(object, &typed.bigint->num, flags);
        break;
    }
    PUSHs(object);

void
and(SV *arg1, SV *arg2, SV *how=NULL)
  ALIAS:
    WEC::SSL::BigInt::or  = 1
    WEC::SSL::BigInt::xor = 2
  PREINIT:
    wec_bigint result, a, b;
    int len, len_a, len_b;
    U8 *buf, *buf_a, *buf_b, *buf_e, *ptr_a, *ptr_b;
    bool negative_a, negative_b;
  PPCODE:
    TAINT_NOT;
    b = SV_BIGINT(arg2, "arg2");
    if (how && (SvGETMAGIC(how), !SvOK(how))) {
        /* $a &= $val */
        result = a = SV_BIGINT_RESULT(arg1, "arg1");
#if SENSITIVE
        a->sensitive |= b->sensitive;
#endif /* SENSITIVE */
    } else {
        a = SV_BIGINT(arg1, "arg1");
        NEW_BIGINT(result, arg1);
#if SENSITIVE
        result->sensitive = a->sensitive | b->sensitive;
#endif /* SENSITIVE */
    }
    len_a = BN_num_bytes(&a->num);
    if (len_a == 0) {
        /* This means a == 0 */
        if (ix) {
            if (!BN_copy(&result->num, &b->num))
                CRYPTO_CROAK("BN_copy error");
        } else
            if (!BN_zero(&result->num)) CRYPTO_CROAK("BN_zero error");
    } else {
        len_b = BN_num_bytes(&b->num);
        if (len_b == 0) {
            /* This means b == 0 */
            if (ix) {
                if (a != result && !BN_copy(&result->num, &a->num))
                    CRYPTO_CROAK("BN_copy error");
            } else
                if (!BN_zero(&result->num)) CRYPTO_CROAK("BN_zero error");
        } else {
            bool negative;
            BIGNUM *bn;
            /* One extra U8 for possible result sign fixup */
            len = len_a + len_b + 1;
            if (len <= 0) croak("length overflow");
            Newx(buf, len, U8);
            buf_a = buf+1;
            buf_b = buf_a + len_a;
            buf_e = buf_b + len_b;

            BN_bn2bin(&a->num, buf_a);
            negative_a = BN_is_negative(&a->num) ? 1 : 0;
            if (negative_a) sign_fixup(buf_a, buf_b);
            BN_bn2bin(&b->num, buf_b);
            negative_b = BN_is_negative(&b->num) ? 1 : 0;
            if (negative_b) sign_fixup(buf_b, buf_e);
            if (len_a < len_b) {
                U8 *b;
                int l;

                b = buf_a;
                buf_a = buf_b;
                buf_b = b;

                negative   = negative_a;
                negative_a = negative_b;
                negative_b = negative;

                l     = len_a;
                len_a = len_b;
                len_b = l;
            }
            /* Big buffer is now a, short buffer is b */
            ptr_a = buf_a + len_a;
            ptr_b = buf_b + len_b;
            switch(ix) {
              case 1:
                /* or */
                while (ptr_b > buf_b) *--ptr_a |= *--ptr_b;
                if (negative_b)
                    while (ptr_a > buf_a) *--ptr_a = 0xff;
                negative = negative_a | negative_b;
                break;
              case 2:
                /* xor */
                while (ptr_b > buf_b) *--ptr_a ^= *--ptr_b;
                if (negative_b)
                    while (ptr_a > buf_a) *--ptr_a ^= 0xff;
                negative = negative_a ^ negative_b;
                break;
              default:
                while (ptr_b > buf_b) *--ptr_a &= *--ptr_b;
                if (!negative_b)
                    while (ptr_a > buf_a) *--ptr_a = 0;
                negative = negative_a & negative_b;
                break;
            }
            if (negative) {
                len_a++;
                *--buf_a = 0xff;
                sign_fixup(buf_a, buf_a + len_a);
            }
            while (len_a > 0 && *buf_a == 0) {
                buf_a++;
                len_a--;
            }
            bn = BN_bin2bn(buf_a, len_a, &result->num);
#if SENSITIVE
            if (result->sensitive) Zero(buf, len, U8);
#endif /* SENSITIVE */
            Safefree(buf);
            if (!bn) CRYPTO_CROAK("BN_bin2bn error");
            if (negative) BN_set_negative(&result->num, 1);
        }
    }
    PUSHs(arg1);

void
rand(SV *arg)
  ALIAS:
    WEC::SSL::BigInt::pseudo_rand = 1
  PREINIT:
    wec_bigint bigint, result;
    SV *object;
    int rc;
  PPCODE:
    TAINT_NOT;
    bigint = SV_BIGINT(arg, "arg");
    NEW_BIGINT(result, object);
    if (!BN_is_zero(&bigint->num) && !RAND_status()) SvTAINTED_on(object);
#if SENSITIVE
    result->sensitive = bigint->sensitive;
#endif /* SENSITIVE */
    rc = ix ?
        BN_pseudo_rand_range(&result->num, &bigint->num) :
        BN_rand_range(       &result->num, &bigint->num);
    if (!rc) CRYPTO_CROAK("rand_range error");
    PUSHs(object);

void
rand_bits(const char *class, ...)
  ALIAS:
    WEC::SSL::BigInt::pseudo_rand_bits = 1
  PREINIT:
    wec_bigint result;
    I32 i;
    const char *name;
    STRLEN len;
    int rc, sensitive;
    bool sens;
    int bits, msb, lsb;
    SV *value, *object;
  PPCODE:
    TAINT_NOT;
    if (items % 2 == 0) croak("Odd number of arguments");
    sens = 0;
    sensitive = -1;
    msb = lsb = bits = -1;
    for (i=1; i<items; i+=2) {
        name = SvPV(ST(i), len);
        value = ST(i+1);
        if (len >= 4) switch(name[0]) {
          case 'b': case 'B':
            if (LOW_EQ(name, len, "bits") ||
                LOW_EQ(name, len, "bit_length")) {
                if (bits >= 0) croak("Multiple bits arguments");
                bits = GET_INT_SENSITIVE(value, sens, "bits");
                if (bits < 0) croak("Negative number of bits");
                goto OK;
            }
            break;
          case 'l': case 'L':
            if (LOW_EQ(name, len, "lsb_ones")) {
                if (lsb >= 0) croak("Multiple lsb_ones arguments");
                lsb = GET_INT_SENSITIVE(value, sens, "lsb_ones");
                if (lsb < 0) croak("Negative number of lsb_ones");
                goto OK;
            }
            break;
          case 'm': case 'M':
            if (LOW_EQ(name, len, "msb_ones")) {
                if (msb >= 0) croak("Multiple msb_ones arguments");
                msb = GET_INT_SENSITIVE(value, sens, "msb_ones");
                if (msb < 0) croak("Negative number of msb_ones");
                goto OK;
            }
            break;
#if SENSITIVE
          case 's': case 'S':
            if (LOW_EQ(name, len, "sensitive")) {
                if (sensitive >= 0) croak("Multiple sensitive arguments");
                sensitive = GET_SENSITIVE(value);
                goto OK;
            }
            break;
#endif /* SENSITIVE */
        }
        croak("Unknown option '%"SVf"'", ST(i));
      OK:;
    }
    if (i != items) croak("Odd number of arguments");
    if (bits < 0) croak("No bits argument");
    if (msb < 0) msb = 0;
    if (msb > bits) croak("More msb_ones than bits");
    if (msb > 2)    croak("More than 2 msb_ones is unsupported");
    if (lsb < 0) lsb = 0;
    if (lsb > bits) croak("More lsb_ones than bits");
    if (lsb > 1)    croak("More than 1 lsb_ones is unsupported");
    NEW_CLASS(result, object, class);
#if SENSITIVE
    result->sensitive = sensitive >= 0 ? sensitive : sens;
#endif /* SENSITIVE */
    if (bits && !RAND_status()) SvTAINTED_on(object);
    rc = ix ?
        BN_pseudo_rand(&result->num, bits, msb-1, lsb) :
        BN_rand(       &result->num, bits, msb-1, lsb);
    if (!rc) CRYPTO_CROAK("Rand error");
    PUSHs(object);

int
bio_print_HEX(SV *integer, SV *bio)
  PREINIT:
    wec_bigint bigint;
    wec_bio the_bio;
  CODE:
    TAINT_NOT;
    bigint = SV_BIGINT(integer, "integer");
    the_bio = SV_TO_BIO(bio, "bio");
    RETVAL = BN_print(the_bio->bio, &bigint->num);
  OUTPUT:
    RETVAL

void
DESTROY(SV *arg)
  PREINIT:
    wec_bigint bigint;
  PPCODE:
    bigint = C_OBJECT(arg, PACKAGE_BASE "::BigInt", "arg");
#if SENSITIVE
    if (bigint->sensitive) BN_clear_free(&bigint->num);
    else
#endif /* SENSITIVE */
    BN_free(&bigint->num);
    Safefree(bigint);

MODULE = WEC::SSL::BigInt		PACKAGE = WEC::SSL::Reciprocal

void
new(SV *class, SV *m)
  PREINIT:
    wec_reciprocal reciprocal;
    wec_bigint bigint;
    SV *object;
    const char *class_name;
  PPCODE:
    TAINT_NOT;
    class_name = C_CLASS(class);
    bigint = SV_BIGINT(m, "m");
    if (BN_is_zero(&bigint->num)) croak("Reciprocal of 0");

    Newx(reciprocal, 1, struct wec_reciprocal);
    BN_RECP_CTX_init(&reciprocal->ctx);
    object = sv_newmortal();
    sv_setref_pv(object, class_name, (void*) reciprocal);
    SvTAINT(object);
#if SENSITIVE
    reciprocal->sensitive = bigint->sensitive;
#endif /* SENSITIVE */
    /* As far as I can determine, the ctx argument is completely unused.
       Sabotage it */
    if (!BN_RECP_CTX_set(&reciprocal->ctx, &bigint->num, (BN_CTX *) -1L))
        CRYPTO_CROAK("BN_RECP_CTX_set error");

    PUSHs(object);

void
sensitive(SV *arg, SV *sensitive=NULL)
  PREINIT:
    wec_reciprocal reciprocal;
  PPCODE:
#if SENSITIVE
    reciprocal = C_OBJECT(arg, PACKAGE_BASE "::Reciprocal", "arg");
    PUSHs(reciprocal->sensitive ? &PL_sv_yes : &PL_sv_no);
    if (sensitive) reciprocal->sensitive = GET_SENSITIVE(sensitive);
#else  /* SENSITIVE */
    croak("Sensitivity not supported");
#endif /* SENSITIVE */

void
taint(SV *arg, SV *taint=NULL)
  PPCODE:
    REF_TAINTED(arg, taint, PACKAGE_BASE "::Reciprocal", "arg");

void
mod_multiply(SV *arg0, SV *arg1, SV *arg2)
  PREINIT:
    BN_CTX *ctx;
    wec_bigint a, b, result;
    wec_reciprocal reciprocal;
    SV *object;
    int rc;
  PPCODE:
    TAINT_NOT;
    a = SV_BIGINT(arg1, "arg1");
    b = SV_BIGINT(arg2, "arg2");
    reciprocal = C_OBJECT(arg0, PACKAGE_BASE "::Reciprocal", "arg0");
    NEW_BIGINT(result, object);
#if SENSITIVE
    result->sensitive = a->sensitive | b->sensitive | reciprocal->sensitive;
#endif /* SENSITIVE */
    ctx = BN_CTX_new();
    if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
    rc = BN_mod_mul_reciprocal(&result->num, &a->num, &b->num,
                               &reciprocal->ctx, ctx);
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK("BN_mod_mul_reciprocal error");
    PUSHs(object);

void
divide(SV *arg0, SV *arg)
  PREINIT:
    BN_CTX *ctx;
    wec_bigint a, big_q, big_r;
    wec_reciprocal reciprocal;
    BIGNUM *r;
    SV *object_q, *object_r;
    int rc;
    U32 gimme;
  PPCODE:
    gimme = GIMME_V;
    if (gimme == G_VOID) XSRETURN_EMPTY;

    TAINT_NOT;
    a = SV_BIGINT(arg, "arg");
    reciprocal = C_OBJECT(arg0, PACKAGE_BASE "::Reciprocal", "arg0");

    NEW_BIGINT(big_q, object_q);
    PUSHs(object_q);
#if SENSITIVE
    big_q->sensitive = a->sensitive | reciprocal->sensitive;
#endif /* SENSITIVE */

    if (gimme == G_ARRAY) {
        NEW_BIGINT(big_r, object_r);
        r = &big_r->num;
        PUSHs(object_r);
#if SENSITIVE
        big_r->sensitive = big_q->sensitive;
#endif /* SENSITIVE */
    } else r = NULL;

    ctx = BN_CTX_new();
    if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
    rc = BN_div_recp(&big_q->num, r, &a->num, &reciprocal->ctx, ctx);
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK("BN_div_recp error");

void
quotient(SV *arg0, SV *arg)
  ALIAS:
    WEC::SSL::Reciprocal::remainder = 1
  PREINIT:
    BN_CTX *ctx;
    wec_bigint a, result;
    wec_reciprocal reciprocal;
    SV *object;
    int rc;
  PPCODE:
    TAINT_NOT;
    a = SV_BIGINT(arg, "arg");
    reciprocal = C_OBJECT(arg0, PACKAGE_BASE "::Reciprocal", "arg0");

    NEW_BIGINT(result, object);
#if SENSITIVE
    result->sensitive = a->sensitive | reciprocal->sensitive;
#endif /* SENSITIVE */

    ctx = BN_CTX_new();
    if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
    if (ix)
        rc = BN_div_recp(NULL, &result->num, &a->num, &reciprocal->ctx, ctx);
    else
        rc = BN_div_recp(&result->num, NULL, &a->num, &reciprocal->ctx, ctx);
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK("BN_div_recp error");
    PUSHs(object);

void
DESTROY(wec_reciprocal reciprocal)
  PPCODE:
#if SENSITIVE
    if (reciprocal->sensitive) {
	BN_clear(&reciprocal->ctx.N);
	BN_clear(&reciprocal->ctx.Nr);
        reciprocal->ctx.num_bits = 0;
        reciprocal->ctx.shift    = 0;
    }
#endif /* SENSITIVE */
    BN_RECP_CTX_free(&reciprocal->ctx);
    Safefree(reciprocal);

MODULE = WEC::SSL::BigInt		PACKAGE = WEC::SSL::Montgomery

void
new(SV *class, SV *m)
  PREINIT:
    wec_montgomery montgomery;
    wec_bigint bigint;
    SV *object;
    BN_CTX *ctx;
    int rc;
    const char *class_name;
  PPCODE:
    TAINT_NOT;
    class_name = C_CLASS(class);
    bigint = SV_BIGINT(m, "m");
    /* Avoid an infinite loop */
    if (BN_is_zero(&bigint->num)) croak("Montgomery of 0");

    Newx(montgomery, 1, struct wec_montgomery);
    BN_MONT_CTX_init(&montgomery->ctx);
    object = sv_newmortal();
    sv_setref_pv(object, class_name, (void*) montgomery);
    SvTAINT(object);
#if SENSITIVE
    montgomery->sensitive = bigint->sensitive;
#endif /* SENSITIVE */

    ctx = BN_CTX_new();
    if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
    rc = BN_MONT_CTX_set(&montgomery->ctx, &bigint->num, ctx);
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK("BN_MONT_CTX_set error");

    PUSHs(object);

void
sensitive(SV *arg, SV *sensitive=NULL)
  PREINIT:
    wec_montgomery montgomery;
  PPCODE:
#if SENSITIVE
    montgomery = C_OBJECT(arg, PACKAGE_BASE "::Montgomery", "arg");
    PUSHs(montgomery->sensitive ? &PL_sv_yes : &PL_sv_no);
    if (sensitive) montgomery->sensitive = GET_SENSITIVE(sensitive);
#else  /* SENSITIVE */
    croak("Sensitivity not supported");
#endif /* SENSITIVE */

void
taint(SV *arg, SV *taint=NULL)
  PPCODE:
    REF_TAINTED(arg, taint, PACKAGE_BASE "::Montgomery", "arg");

void
mod_multiply(SV *arg0, SV *arg1, SV *arg2)
  PREINIT:
    BN_CTX *ctx;
    wec_bigint a, b, result;
    wec_montgomery montgomery;
    SV *object;
    int rc;
  PPCODE:
    TAINT_NOT;
    a = SV_BIGINT(arg1, "arg1");
    b = SV_BIGINT(arg2, "arg2");
    montgomery = C_OBJECT(arg0, PACKAGE_BASE "::Montgomery", "arg0");
    NEW_BIGINT(result, object);
#if SENSITIVE
    result->sensitive = a->sensitive | b->sensitive | montgomery->sensitive;
#endif /* SENSITIVE */
    ctx = BN_CTX_new();
    if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
    rc = BN_mod_mul_montgomery(&result->num, &a->num, &b->num,
                               &montgomery->ctx, ctx);
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK("BN_mod_mul_montgomery error");
    PUSHs(object);

void
from(SV *arg0, SV *arg)
  ALIAS:
    WEC::SSL::Montgomery::to = 1
  PREINIT:
    BN_CTX *ctx;
    wec_bigint a, result;
    wec_montgomery montgomery;
    SV *object;
    int rc;
  PPCODE:
    TAINT_NOT;
    a = SV_BIGINT(arg, "arg");
    montgomery = C_OBJECT(arg0, PACKAGE_BASE "::Montgomery", "arg0");

    NEW_BIGINT(result, object);
    PUSHs(object);
#if SENSITIVE
    result->sensitive = a->sensitive | montgomery->sensitive;
#endif /* SENSITIVE */

    ctx = BN_CTX_new();
    if (!ctx) CRYPTO_CROAK("BN_CTX_new error");
    if (ix)
        rc = BN_to_montgomery(  &result->num, &a->num, &montgomery->ctx, ctx);
    else
        rc = BN_from_montgomery(&result->num, &a->num, &montgomery->ctx, ctx);
    BN_CTX_free(ctx);
    if (!rc) CRYPTO_CROAK("Montgomery reduction error");

void
_R(SV *arg0)
  ALIAS:
    WEC::SSL::Montgomery::_N = 1
    WEC::SSL::Montgomery::_Ni = 2
  PREINIT:
    wec_bigint result;
    wec_montgomery montgomery;
    SV *object;
  PPCODE:
    TAINT_NOT;
    montgomery = C_OBJECT(arg0, PACKAGE_BASE "::Montgomery", "arg0");

    NEW_BIGINT(result, object);
    PUSHs(object);
#if SENSITIVE
    result->sensitive = montgomery->sensitive;
#endif /* SENSITIVE */
    if (!BN_copy(&result->num, ix == 0 ? &montgomery->ctx.RR :
                 ix == 1 ? &montgomery->ctx.N :
                 &montgomery->ctx.Ni))
        CRYPTO_CROAK("BN_copy error");

void
DESTROY(wec_montgomery montgomery)
  PPCODE:
#if SENSITIVE
    if (montgomery->sensitive) {
	BN_clear(&montgomery->ctx.RR);
	BN_clear(&montgomery->ctx.N);
	BN_clear(&montgomery->ctx.Ni);
        montgomery->ctx.ri = 0;
        montgomery->ctx.n0 = 0;
    }
#endif /* SENSITIVE */
    BN_MONT_CTX_free(&montgomery->ctx);
    Safefree(montgomery);

BOOT:
    init_utils();
