#include "wec_ssl.h"
#include <limits.h>

/* target is lowercase, ends in 0, and lengths are already equal */
static int low_eq(const char *name, const char *target) {
    while (*target) {
        if (toLOWER(*name) != *target++) return 0;
        name++;
    }
    return 1;
}

/* Return downgraded version of the SV string */
static const U8 *sv_bytes(pTHX_ SV *sv, STRLEN *l) {
    const U8 *string, *str_end, *from;
    STRLEN len;

    string = SvPV(sv, len);
    if (SvUTF8(sv)) {
        U32 utf8_flags;

        utf8_flags = ckWARN(WARN_UTF8) ? 0 : UTF8_ALLOW_ANY;
        str_end = string + len;
        for (from = string; from < str_end; from++) {
            if (!UNI_IS_INVARIANT(*from)) {
                /* We have real UTF8 */
                U8 *temp, *to;
                UV ch;
                STRLEN temp_len;

                Newx(temp, len+1, U8);
                temp_len = from - string;
                Copy(string, temp, temp_len, U8);
                to = temp + temp_len;
                for (; from < str_end; from += temp_len) {
                    ch = utf8n_to_uvchr((U8 *) from, str_end-from, &temp_len,
                                        utf8_flags);
                    if (temp_len == (STRLEN) -1 || temp_len == 0) {
                        Safefree(temp);
                        croak("Malformed UTF-8");
                    }
                    if (ch >= 0x100) {
                        Safefree(temp);
                        croak("UTF-8 string can't be downgraded");
                    }
                    *to++ = ch;
                }
                *to = 0;
                SAVEFREEPV(temp);
                *l = to-temp;
                return temp;
            }
        }
        /* Nothing in the string is actually encoded */
    }
    *l = len;
    return string;
}

/* Return canonical (downgraded if downgrading possible) version of
   the SV string */
static const U8 *sv_canonical(pTHX_ SV *sv, STRLEN *l) {
    const U8 *string, *str_end, *from;
    STRLEN len, temp_len, converted_len;
    UV ch;
    U32 utf8_flags;
    U8 *temp, *to;

    string = SvPV(sv, len);
    if (!SvUTF8(sv)) {
        /* Already downgraded, so clearly canonical */
        *l = len;
        return string;
    }
    str_end = string + len;
    utf8_flags = ckWARN(WARN_UTF8) ? 0 : UTF8_ALLOW_ANY;
    converted_len = 0;
    for (from = string; from < str_end; from += temp_len) {
        ch = utf8n_to_uvchr((U8 *) from, str_end-from, &temp_len, utf8_flags);
        if (temp_len == (STRLEN) -1 || temp_len == 0) croak("Malformed UTF-8");
        if (ch >= 0x100) {
            /* Really has high ascii, so clearly canonical */
            *l = len;
            return string;
        }
        converted_len++;
    }

    /* String has no real reason to be UTF8. Convert */
    Newx(temp, converted_len+1, U8);
    to = temp;
    for (from = string; from < str_end; from += temp_len) {
        ch = utf8n_to_uvchr((U8 *) from, str_end-from, &temp_len,
                            UTF8_ALLOW_ANY);
        if (temp_len == (STRLEN) -1 || temp_len == 0) {
            Safefree(temp);
            croak("Malformed UTF-8");
        }
        if (ch >= 0x100) {
            Safefree(temp);
            croak("Assert: Second conversion gives high code %d", (int) ch);
        }
        *to++ = ch;
    }
    *to = 0;
    if (to-temp != converted_len) {
        Safefree(temp);
        croak("Assert: Second conversion gives different length (%"IVdf" vs %"UVuf")", (IV) (to-temp), (UV) converted_len);
    }
    SAVEFREEPV(temp);
    *l = converted_len;
    return temp;
}

static const char *sv_file(pTHX_ SV *sv) {
    const U8 *string, *str_end, *from;
    U8 *temp, *to;
    UV ch;
    STRLEN len, temp_len;
    U32 utf8_flags;

    string = SvPV(sv, len);
    if (len == 0) croak("Empty path name");
    if (string[len]) croak("Missing terminating \\0 in perl string");
    if (SvUTF8(sv)) {
        str_end = string + len;
        for (from = string; from < str_end; from++) {
            if (!UNI_IS_INVARIANT(*from)) {
                /* We have real UTF8 */
                utf8_flags = ckWARN(WARN_UTF8) ? 0 : UTF8_ALLOW_ANY;
                Newx(temp, len+1, U8);
                temp_len = from - string;
                Copy(string, temp, temp_len, U8);
                to = temp+temp_len;
                for (; from < str_end; from += temp_len) {
                    ch = utf8n_to_uvchr((U8*) from, str_end-from, &temp_len,
                                        utf8_flags);
                    if (temp_len == (STRLEN) -1 || temp_len == 0) {
                        Safefree(temp);
                        croak("Malformed UTF-8");
                    }
                    if (ch >= 0x100) {
                        Safefree(temp);
                        croak("UTF-8 string can't be downgraded");
                    }
                    if (ch == 0) {
                        Safefree(temp);
                        croak("filename contains \\0");
                    }
                    *to++ = ch;
                }
                *to = 0;
                SAVEFREEPV(temp);
                return (char *) temp;
            }
            if (!*from) croak("filename contains \\0");
        }
        /* Nothing in the string is actually encoded */
    } else if (len != strlen(string)) croak("filename contains \\0");
    return string;
}

/* We should probably try to find the first real utf8 char --Ton */
static STRLEN utf8_copy(pTHX_ U8 *to,   STRLEN to_len,
                        const U8 *from, STRLEN from_len) {
    U8 *t;
    const U8 *f, *from_end, *to_end;
    STRLEN retlen;
    UV ch;
    U32 utf8_flags  = ckWARN(WARN_UTF8) ? 0 : UTF8_ALLOW_ANY;

    from_end = from + from_len;
    to_end   = to   + to_len;
    t = to;
    for (f = from; f < from_end && t < to_end; f += retlen) {
        ch = utf8n_to_uvchr((U8 *) f, to_end-t, &retlen, utf8_flags);
        if (retlen == (STRLEN) -1 || retlen == 0)
            croak("Malformed UTF-8 string in downgrade");
        if (ch >= 0x100) croak("Cannot downgrade string");
        *t++ = ch;
    }
    return t-to;
}

static wec_bio sv_to_bio(pTHX_ SV **sv_bio, const char *parameter_name) {
    IV tmp;
    wec_bio_chain chain;
    wec_bio bio;

    if (!*sv_bio) croak("No %s argument", parameter_name);
    if (!SvOK(*sv_bio)) croak("Undefined %s argument", parameter_name);

    if (sv_derived_from(*sv_bio, PACKAGE_BASE "::BioChain")) {
        if (!SvROK(*sv_bio))
            croak("Not really a " PACKAGE_BASE "::BioChain object");
        *sv_bio = SvRV(*sv_bio);
        tmp = SvIV(*sv_bio);
        if (!tmp)
            croak("%s is not really a " PACKAGE_BASE "::BioChain object",
                  parameter_name);
        chain = INT2PTR(wec_bio_chain, tmp);
        if (chain->ssl) croak("%s chain is part of an SSL object",
                              parameter_name);
        if (!chain->nr_bio) croak("%s chain is empty", parameter_name);
        tmp = SvIV(chain->bio[0]);
        bio = INT2PTR(wec_bio, tmp);
    } else if (sv_derived_from(*sv_bio, PACKAGE_BASE "::Bio")) {
        if (!SvROK(*sv_bio))
            croak("Not really a " PACKAGE_BASE "::Bio object");
        *sv_bio = SvRV(*sv_bio);
        tmp = SvIV(*sv_bio);
        if (!tmp)
            croak("%s is not really a " PACKAGE_BASE "::Bio object",
                  parameter_name);
        bio = INT2PTR(wec_bio, tmp);
        if (bio->chain) croak("%s argument is part of a BIO chain",
                              parameter_name);
        if (bio->ssl) croak("%s argument is part of an SSL object",
                            parameter_name);
    } else croak("%s argument is neither a BIO nor a BIO chain",
                 parameter_name);
    return bio;
}

/* Check that the given SV represents a plain ASCII C-style string
   Return that string
*/
/* Probably we should have a variant that lowers lowerable strings --Ton */
#define c_class(class) c_ascii(aTHX_ class, "class")
static const char *c_ascii(pTHX_ SV *sv_string, const char *context) {
    const char *string;
    STRLEN len, l;

    string = SvPV(sv_string, len);
    if (string[len]) croak("%s perl string does not end in \\0", context);
    for (l=0; l<len; l++) {
        if (string[l] == 0) croak("%s contains \\0", context);
        /* Abuse knowledge that high ascii UTF8 is encode starting with a
           high ascii byte. This is invalid for EBCDIC, where we'd need to
           distinguish cases based on SvUTF8 */
        if (!UNI_IS_INVARIANT(string[l]))
            croak("%s contains high chars", context);
    }
    return string;
}

static void crypto_croak(const char *fallback, ...) __attribute__((noreturn));
static void crypto_croak(const char *fallback, ...) {
    int flags, line;
    const char *file, *data;
    unsigned long code;
    SV *err_sv, *tmp;
    AV *err_av;
    HV *err_stash, *err_hv;
    dTHX;

    code = ERR_get_error_line_data(&file, &line, &data, &flags);
    if (!code) {
        va_list args;
        va_start(args, fallback);
        Perl_vcroak(aTHX_ fallback, &args);
        /* NOTREACHED */
        va_end(args);
    }

    err_stash = gv_stashpv(PACKAGE_BASE "::Error", 1);
    if (!err_stash) croak("Assert: Could not create error stash");

    err_sv = get_sv("@", TRUE);
    tmp = newSVrv(err_sv, PACKAGE_BASE "::Errors");
    SvUPGRADE(tmp, SVt_PVHV);
    err_hv = (HV *) tmp;

    err_av = newAV();
    tmp = newRV_noinc((SV *) err_av);
    if (!hv_store(err_hv, "errors", 6, tmp, 0)) {
        SvREFCNT_dec(tmp);
        croak("Assert: hv_store failed");
    }

    tmp = Perl_mess(aTHX_ "");
    tmp = newSVsv(tmp);
    if (!hv_store(err_hv, "where", 5, tmp, 0)) {
        SvREFCNT_dec(tmp);
        croak("Assert: hv_store failed");
    }

    do {
        char buf[1024];
        const char *ptr, *end, *next;
        HV *err_hv;
        SV *rv;
	UV uv;

        err_hv = newHV();
        rv = newRV_noinc((SV *) err_hv);
        sv_bless(rv, err_stash);
        av_push(err_av, rv);

        tmp = newSVuv(code);
        if (!hv_store(err_hv, "code", 4, tmp, 0)) {
            SvREFCNT_dec(tmp);
            croak("Assert: hv_store failed");
        }
        if (flags & ERR_TXT_STRING) {
            tmp = newSVpv(data, 0);
            if (!hv_store(err_hv, "data", 4, tmp, 0)) {
                SvREFCNT_dec(tmp);
                croak("Assert: hv_store failed");
            }
        }
        tmp = newSVpv(file, 0);
        if (!hv_store(err_hv, "c_file", 6, tmp, 0)) {
            SvREFCNT_dec(tmp);
            croak("Assert: hv_store failed");
        }
        tmp = newSVuv(line);
        if (!hv_store(err_hv, "c_line", 6, tmp, 0)) {
            SvREFCNT_dec(tmp);
            croak("Assert: hv_store failed");
        }

        ERR_error_string_n(code, buf, sizeof(buf));
        end = buf + sizeof(buf)-1;

        /* Skip error: */
        if (memcmp(buf, "error:", 6))
            Perl_croak(aTHX_ "Unexpected error '%s'", buf);

        /* Skip code in hex */
        ptr = memchr(buf+6, ':', sizeof(buf)-6);
        if (!ptr || ptr != buf + 6 + 8)
            Perl_croak(aTHX_ "Unexpected error '%s'", buf);
        ptr++;

        /* Find package */
        next = memchr(ptr, ':', end-ptr);
        if (!next) Perl_croak(aTHX_ "Unexpected error '%s'", buf);
        tmp = newSVpvn(ptr, next-ptr);
	uv = ERR_GET_LIB(code);
	sv_setuv(tmp, uv);
        SvPOK_on(tmp);
        if (!hv_store(err_hv, "c_library", 9, tmp, 0)) {
            SvREFCNT_dec(tmp);
            croak("Assert: hv_store failed");
        }
        ptr = next+1;

        /* Find routine */
        next = memchr(ptr, ':', end-ptr);
        if (!next) croak("Unexpected error '%s'", buf);
        tmp = newSVpvn(ptr, next-ptr);
        uv = ERR_GET_FUNC(code);
	sv_setuv(tmp, uv);
        SvPOK_on(tmp);
        if (!hv_store(err_hv, "c_function", 10, tmp, 0)) {
            SvREFCNT_dec(tmp);
            croak("Assert: hv_store failed");
        }
        ptr = next+1;

        /* Find error */
        tmp = newSVpv(ptr, 0);
        uv = ERR_GET_REASON(code);
	sv_setuv(tmp, uv);
        SvPOK_on(tmp);
        if (!hv_store(err_hv, "reason", 6, tmp, 0)) {
            SvREFCNT_dec(tmp);
            croak("Assert: hv_store failed");
        }

        /* Not sure if user errors above 99 count as fatal
        if (ERR_FATAL_ERROR(code)) {
            if (!hv_store(err_hv, "fatal", 5, &PL_sv_yes, 0))
                croak("Assert: hv_store failed");
        }
        */

        code = ERR_get_error_line_data(&file, &line, &data, &flags);
    } while (code);

    Perl_croak(aTHX_ Nullch);
}

static bool ciphers_loaded = 0;
static const EVP_CIPHER *cipher_by_name(pTHX_ SV *name) {
    char *cipher_name;
    STRLEN len;
    const EVP_CIPHER *cipher;

    if (!ciphers_loaded) {
        OpenSSL_add_all_ciphers();
        ciphers_loaded = 1;
    }

    cipher_name = SvPV(name, len);
    if (cipher_name[len]) 
        croak("Assertion: cipher name is not \\0-terminated");
    if (memchr(cipher_name, 0, len)) croak("Engine name contains \\0");
    /* No need for an unicode check, all valid names are pure ASCII */
    cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) croak("Unknown cipher '%"SVf"'", name);
    return cipher;
}

static bool digests_loaded = 0;
static const EVP_MD *digest_by_name(pTHX_ SV *name) {
    char *digest_name;
    STRLEN len;
    const EVP_MD *digest;

    if (!digests_loaded) {
        OpenSSL_add_all_digests();
        digests_loaded = 1;
    }

    digest_name = SvPV(name, len);
    if (digest_name[len]) 
        croak("Assertion: digest name is not \\0-terminated");
    if (memchr(digest_name, 0, len)) croak("Digest name contains \\0");
    /* No need for an unicode check, all valid names are pure ASCII */
    digest = EVP_get_digestbyname(digest_name);
    if (!digest) croak("Unknown digest '%"SVf"'", name);
    return digest;
}

/* should do ENGINE_cleanup() at program end if this is 1 --Ton */
static bool engines_loaded = 0;
static void load_engines(void) {
    if (!engines_loaded) {
        ENGINE_load_builtin_engines();
        engines_loaded = 1;
    }
}

static ENGINE *engine_by_name(pTHX_ SV *name) {
    char *engine_name;
    STRLEN len;
    ENGINE *e;

    load_engines();
    engine_name = SvPV(name, len);
    if (engine_name[len]) 
        croak("Assertion: engine name is not \\0-terminated");
    if (memchr(engine_name, 0, len)) croak("Engine name contains \\0");
    /* No need for an unicode check, all valid names are pure ASCII */
    e = ENGINE_by_id(engine_name);
    return e;
}

static int try_cipher(pTHX_ const char *name, STRLEN len, SV *value,
                      const EVP_CIPHER **cipher) {
    if (len != 6 || !low_eq(name, "cipher")) return 0;
    if (*cipher) croak("Multiple cipher arguments");
    *cipher = cipher_by_name(aTHX_ value);
    return 1;
}

static int try_digest(pTHX_ const char *name, STRLEN len, SV *value,
                      const EVP_MD **digest) {
    if (len != 6 || !low_eq(name, "digest")) return 0;
    if (*digest) croak("Multiple digest arguments");
    *digest = digest_by_name(aTHX_ value);
    return 1;
}

static int try_engine(pTHX_ const char *name, STRLEN len, SV *value,
                      const ENGINE **engine) {
    ENGINE *e;

    if (len != 6 || !low_eq(name, "engine")) return 0;
    if (*engine) croak("Multiple engine arguments");
    e = engine_by_name(aTHX_ value);
    if (!e) crypto_croak("Engine '%"SVf"' is not available", value);
    *engine = e;
    return 1;
}

#define ERR_FETCH(error, name)	\
	err_fetch(aTHX_ error, name, sizeof("" name) -1, 1)

static SV *err_fetch(pTHX_ SV *error, const char *name, I32 name_len,
                     bool must_exist) {
    HV *err_hv;
    SV **ptr;

    if (!sv_derived_from(error, PACKAGE_BASE "::Error")) {
        if (!SvOK(error)) croak("error is undefined");
        croak("error is not of type " PACKAGE_BASE "::Error");
    }
    if (!SvROK(error)) croak("error is not a reference");
    err_hv = (HV *) SvRV(error);
    if (SvTYPE(err_hv) != SVt_PVHV) croak("error is not a HASH reference");
    ptr = hv_fetch(err_hv, name, name_len, 0);
    if (!ptr) {
        if (must_exist) croak("No %.*s entry", (int) name_len, name);
        return &PL_sv_undef;
    }
    return *ptr;
}

#define ERRS_FETCH(error, name)	\
	errs_fetch(aTHX_ error, name, sizeof("" name) -1)

static SV *errs_fetch(pTHX_ SV *errors, const char *name, I32 name_len) {
    HV *err_hv;
    SV **ptr;

    if (!sv_derived_from(errors, PACKAGE_BASE "::Errors")) {
        if (!SvOK(errors)) croak("errors is undefined");
        croak("errors is not of type " PACKAGE_BASE "::Errors");
    }
    if (!SvROK(errors)) croak("errors is not a reference");
    err_hv = (HV *) SvRV(errors);
    if (SvTYPE(err_hv) != SVt_PVHV) croak("errors is not a HASH reference");
    ptr = hv_fetch(err_hv, name, name_len, 0);
    if (!ptr) croak("No %.*s entry", (int) name_len, name);
    return *ptr;
}

static void error_string(pTHX_ SV *result, SV *error) {
    HV *err_hv;
    SV **e_ptr, **d_ptr, **c_ptr;
    UV code;

    if (!sv_derived_from(error, PACKAGE_BASE "::Error")) {
        if (!SvOK(error)) croak("error is undefined");
        croak("error is not of type " PACKAGE_BASE "::Error");
    }

    if (!SvROK(error)) croak("error is not a reference");
    err_hv = (HV *) SvRV(error);
    if (SvTYPE(err_hv) != SVt_PVHV) croak("error is not a HASH reference");
    e_ptr = hv_fetch(err_hv, "reason", 6, 0);
    if (!e_ptr) croak("No error entry");

    d_ptr = hv_fetch(err_hv, "data", 4, 0);
    if (!d_ptr) sv_catsv(result, *e_ptr);
    else sv_catpvf(result, "%"SVf" (%"SVf")", *e_ptr, *d_ptr);

    c_ptr = hv_fetch(err_hv, "code", 4, 0);
    if (!c_ptr) croak("No code entry");

    SvUPGRADE(result,SVt_PVNV);
    if (SvUOK(*c_ptr)) {
	SvUV_set(result, SvUV(*c_ptr));
	SvIOK_on(result);
	SvIsUV_on(result);
    } else {
	SvIV_set(result, SvIV(*c_ptr));
	SvIOK_on(result);
    }
}

/* Duplicate from perl source (since it's not exported unfortunately) */
static void not_a_number(pTHX_ SV *sv, const char *from, STRLEN len) {
    SV *dsv;
    char tmpbuf[64];
    char *pv;

    if (DO_UTF8(sv)) {
        dsv = sv_2mortal(newSVpv("", 0));
        pv = Perl_pv_uni_display(aTHX_ dsv, (U8*) from, len, 10, 0);
    } else {
        char *d = tmpbuf;
        char *limit = tmpbuf + sizeof(tmpbuf) - 8;
        /* each *s can expand to 4 chars + "...\0",
           i.e. need room for 8 chars */

        const char *s, *end;
        for (s = from, end = s + len; s < end && d < limit; s++) {
            int ch = *s & 0xFF;
            if (ch & 128 && !isPRINT_LC(ch)) {
                *d++ = 'M';
                *d++ = '-';
                ch &= 127;
            }
            if (ch == '\n') {
                *d++ = '\\';
                *d++ = 'n';
            }
            else if (ch == '\r') {
                *d++ = '\\';
                *d++ = 'r';
            }
            else if (ch == '\f') {
                *d++ = '\\';
                *d++ = 'f';
            }
            else if (ch == '\\') {
                *d++ = '\\';
                *d++ = '\\';
            }
            else if (ch == '\0') {
                *d++ = '\\';
                *d++ = '0';
            }
            else if (isPRINT_LC(ch))
                *d++ = ch;
            else {
                *d++ = '^';
                *d++ = toCTRL(ch);
            }
        }
        if (s < end) {
            *d++ = '.';
            *d++ = '.';
            *d++ = '.';
        }
        *d = '\0';
        pv = tmpbuf;
    }
    Perl_warner(aTHX_ packWARN(WARN_NUMERIC),
                "Argument \"%s\" isn't numeric", pv);
}

/* Workaround for older perls without packWARN */
#ifndef packWARN
# define packWARN(a) (a)
#endif

/* Duplicate from perl source (since it's not exported unfortunately) */
static bool my_isa_lookup(pTHX_ HV *stash, const char *name, HV* name_stash,
                          int len, int level) {
    AV* av;
    GV* gv;
    GV** gvp;
    HV* hv = Nullhv;
    SV* subgen = Nullsv;

    /* A stash/class can go by many names (ie. User == main::User), so
       we compare the stash itself just in case */
    if ((name_stash && stash == name_stash) ||
        strEQ(HvNAME(stash), name) ||
        strEQ(name, "UNIVERSAL")) return TRUE;

    if (level > 100) croak("Recursive inheritance detected in package '%s'",
                           HvNAME(stash));

    gvp = (GV**)hv_fetch(stash, "::ISA::CACHE::", 14, FALSE);

    if (gvp && (gv = *gvp) != (GV*)&PL_sv_undef && (subgen = GvSV(gv)) &&
        (hv = GvHV(gv))) {
        if (SvIV(subgen) == (IV)PL_sub_generation) {
            SV* sv;
            SV** svp = (SV**)hv_fetch(hv, name, len, FALSE);
            if (svp && (sv = *svp) != (SV*)&PL_sv_undef) {
                DEBUG_o( Perl_deb(aTHX_ "Using cached ISA %s for package %s\n",
                                  name, HvNAME(stash)) );
                return sv == &PL_sv_yes;
            }
        } else {
            DEBUG_o( Perl_deb(aTHX_ "ISA Cache in package %s is stale\n",
                              HvNAME(stash)) );
            hv_clear(hv);
            sv_setiv(subgen, PL_sub_generation);
        }
    }

    gvp = (GV**)hv_fetch(stash,"ISA",3,FALSE);

    if (gvp && (gv = *gvp) != (GV*)&PL_sv_undef && (av = GvAV(gv))) {
	if (!hv || !subgen) {
	    gvp = (GV**)hv_fetch(stash, "::ISA::CACHE::", 14, TRUE);

	    gv = *gvp;

	    if (SvTYPE(gv) != SVt_PVGV)
		gv_init(gv, stash, "::ISA::CACHE::", 14, TRUE);

	    if (!hv)
		hv = GvHVn(gv);
	    if (!subgen) {
		subgen = newSViv(PL_sub_generation);
		GvSV(gv) = subgen;
	    }
	}
	if (hv) {
	    SV** svp = AvARRAY(av);
	    /* NOTE: No support for tied ISA */
	    I32 items = AvFILLp(av) + 1;
	    while (items--) {
		SV* sv = *svp++;
		HV* basestash = gv_stashsv(sv, FALSE);
		if (!basestash) {
		    if (ckWARN(WARN_MISC))
			Perl_warner(aTHX_ packWARN(WARN_SYNTAX),
                                    "Can't locate package %"SVf" for @%s::ISA",
                                    sv, HvNAME(stash));
		    continue;
		}
		if (my_isa_lookup(aTHX_ basestash, name, name_stash,
                                  len, level + 1)) {
		    (void)hv_store(hv,name,len,&PL_sv_yes,0);
		    return TRUE;
		}
	    }
	    (void)hv_store(hv,name,len,&PL_sv_no,0);
	}
    }
    return FALSE;
}

/* Caller is responsible for doing SvGETMAGIC(object) */
static void *c_sv(pTHX_ SV *object, const char *class, const char *context) {
    SV *sv;
    HV *stash, *class_stash;

    if (!SvOK(object)) {
        if (!context) return NULL;
        croak("%s is tondefined", context);
    }
    if (!SvROK(object)) {
        if (!context) return NULL;
        if (SvOK(object)) croak("%s is not a reference", context);
        croak("%s is undefined", context);
    }
    sv = SvRV(object);
    if (!SvOBJECT(sv)) {
        if (context) croak("%s is not an object reference", context);
        return NULL;
    }
    stash = SvSTASH(sv);
    /* Is the next even possible ? */
    if (!stash) {
        if (context) croak("%s is not a typed reference", context);
        return NULL;
    }
    class_stash = gv_stashpv(class, FALSE);
    if (!my_isa_lookup(aTHX_ stash, class, class_stash, strlen(class), 0)) {
        if (context) croak("%s is not a %s reference", context, class);
        return NULL;
    }
    return sv;
}

static void *c_object(pTHX_ SV *object, const char *class, const char *context)
{
    SV *sv;
    IV address;

    SvGETMAGIC(object);
    sv = c_sv(aTHX_ object, class, context);
    if (!sv) return NULL;
    address = SvIV(sv);
    if (!address) croak("%s object has a NULL pointer", context);
    return INT2PTR(void *, address);
}

static int get_int(pTHX_ SV *value, 
#if SENSITIVE
                   bool *sensitive,
#endif /* SENSITIVE */
                   const char *context) {
    wec_bigint bigint;
    NV nval;

    bigint = c_object(aTHX_ value, PACKAGE_BASE "::BigInt", NULL);
    if (bigint) {
        if (bigint->num.top == 0) {
#if SENSITIVE
            if (bigint->sensitive && sensitive) *sensitive = 1;
#endif /* SENSITIVE */
            return 0;
        }
        if (bigint->num.top > 1) croak("%s out of range", context);
        if (bigint->num.d[0] > INT_MAX)
            croak("%s %.0"NVff" out of range", context,
                  BN_is_negative(&bigint->num) ?
                  -(NV) bigint->num.d[0] : (NV) bigint->num.d[0]);
#if SENSITIVE
        if (bigint->sensitive && sensitive) *sensitive = 1;
#endif /* SENSITIVE */
        return BN_is_negative(&bigint->num) ?
            -(int) bigint->num.d[0] : (int) bigint->num.d[0];
    }

    if (!SvOK(value)) {
        if (ckWARN(WARN_UNINITIALIZED))
            Perl_report_uninit(aTHX_ value);
        return 0;
    }

    /* Try to access the value as an IV/UV */
    if (SvIOKp(value)) {
        IV iv;
        if (SvIsUV(value)) {
            UV uv = SvUVX(value);
            if (uv > INT_MAX) croak("%s %"UVuf" out of range", context, uv);
            return uv;
        }
        iv = SvIVX(value);
        if ( iv < -INT_MAX || -iv < -INT_MAX)
            croak("%s %"IVdf" out of range", context, iv);
        return iv;
    }

    if (SvNOKp(value)) nval = SvNVX(value);
    else if (SvPOKp(value) && SvLEN(value)) {
        if (ckWARN(WARN_NUMERIC) &&
            !grok_number(SvPVX(value), SvCUR(value), NULL))
            not_a_number(aTHX_ value, SvPVX(value), SvCUR(value));
        nval = Atof(SvPVX(value));
    } else nval = SvNV(value);
    if (nval >=  1+(NV) INT_MAX ||
        nval <= -1-(NV) INT_MAX)
        croak("%s %"NVgf" out of range", context, nval);
    return nval;
}

static long get_long(pTHX_ SV *value, const char *context) {
    wec_bigint bigint;
    NV nval;
    long result;
    int n;

    bigint = c_object(aTHX_ value, PACKAGE_BASE "::BigInt", NULL);
    if (bigint) {
        if (bigint->num.top == 0) return 0;
        if (BN_num_bits(&bigint->num) > sizeof(long)*CHAR_BIT-1)
            croak("%s out of range", context);
        n = bigint->num.top;
        result = bigint->num.d[--n];
#if ULONG_MAX > BN_MASK2
        while (--n >= 0) {
            result <<= BN_BITS2;
            result |= bigint->num.d[n] & BN_MASK2;
        }
#endif
        return BN_is_negative(&bigint->num) ? -result : result;
    }

    if (!SvOK(value)) {
        if (ckWARN(WARN_UNINITIALIZED))
            Perl_report_uninit(aTHX_ value);
        return 0;
    }

    /* Try to access the value as an IV/UV */
    if (SvIOKp(value)) {
        IV iv;
        if (SvIsUV(value)) {
            UV uv = SvUVX(value);
            if (uv > LONG_MAX) croak("%s %"UVuf" out of range", context, uv);
            return uv;
        }
        iv = SvIVX(value);
        if ( iv < -LONG_MAX || -iv < -LONG_MAX)
            croak("%s %"IVdf" out of range", context, iv);
        return iv;
    }

    if (SvNOKp(value)) nval = SvNVX(value);
    else if (SvPOKp(value) && SvLEN(value)) {
        if (ckWARN(WARN_NUMERIC) &&
            !grok_number(SvPVX(value), SvCUR(value), NULL))
            not_a_number(aTHX_ value, SvPVX(value), SvCUR(value));
        nval = Atof(SvPVX(value));
    } else nval = SvNV(value);
    if (nval >=  1+(NV) LONG_MAX ||
        nval <= -1-(NV) LONG_MAX)
        croak("%s %"NVgf" out of range", context, nval);
    return nval;
}

static UV get_UV(pTHX_ SV *value, const char *context) {
    wec_bigint bigint;
    NV nval;
    UV result;
    int n;

    bigint = c_object(aTHX_ value, PACKAGE_BASE "::BigInt", NULL);
    if (bigint) {
        if (bigint->num.top == 0) return 0;
        if (BN_is_negative(&bigint->num)) croak("%s is negative", context);
        if (BN_num_bits(&bigint->num) > sizeof(UV)*CHAR_BIT)
            croak("%s out of range", context);
        n = bigint->num.top;
        result = bigint->num.d[--n];
        while (--n >= 0) {
            result <<= BN_BITS2;
            result |= bigint->num.d[n] & BN_MASK2;
        }
        return result;
    }

    if (!SvOK(value)) {
        if (ckWARN(WARN_UNINITIALIZED))
            Perl_report_uninit(aTHX_ value);
        return 0;
    }

    /* Try to access the value as an IV/UV */
    if (SvIOKp(value)) {
        IV iv;
        if (SvIsUV(value)) return SvUVX(value);
        iv = SvIVX(value);
        if (iv < 0) croak("%s %"IVdf" is negative", context, iv);
        return iv;
    }

    if (SvNOKp(value)) nval = SvNVX(value);
    else if (SvPOKp(value) && SvLEN(value)) {
        if (ckWARN(WARN_NUMERIC) &&
            !grok_number(SvPVX(value), SvCUR(value), NULL))
            not_a_number(aTHX_ value, SvPVX(value), SvCUR(value));
        nval = Atof(SvPVX(value));
    } else nval = SvNV(value);
    if (nval < 0) croak("%s %"NVgf" is negative", context, nval);
    if (nval >=  1+(NV) UV_MAX)
        croak("%s %"NVgf" out of range", context, nval);
    return nval;
}

/* Only taint the object, not the reference */
#define HALF_TAINT 0

static SV *ref_tainted(pTHX_ SV *arg, SV *tainted,
                       const char *class, const char *context) {
    if (PL_tainting) {
        SV *object;
        bool was_tainted;

        SvGETMAGIC(arg);
        object = c_sv(aTHX_ arg, class, context);
        was_tainted = SvTAINTED(object);
        if (tainted) {
            TAINT_NOT;
            if (SvTRUE(tainted)) {
                if (!was_tainted) sv_taint(object);
#if !HALF_TAINT
                sv_taint(arg);
#endif /* HALF_TAINT */
            } else {
                if (PL_tainted)
                    croak("Turning tainting off using a tainted value");
#if !HALF_TAINT
                sv_untaint(arg);
#endif /* HALF_TAINT */
                if (was_tainted) sv_untaint(object);
            }
        }
        return was_tainted ? &PL_sv_yes : &PL_sv_no;
    } else {
        if (SvTRUE(tainted)) croak("Can't taint in a non tainted perl");
        return &PL_sv_no;
    }
}

struct util utils;

MODULE = WEC::SSL::Utils		PACKAGE = WEC::SSL::Utils
PROTOTYPES: ENABLE

void
fchmod(int fd, int mode)
  PPCODE:
    TAINT_PROPER("fchmod");
    PUSHs(fchmod(fd, mode) ? &PL_sv_undef : &PL_sv_yes);

void
_true(SV *sv=NULL, SV* dummy=NULL, SV *how=NULL)
  PPCODE:
    XPUSHs(&PL_sv_yes);

void
_false(SV *sv=NULL, SV* dummy=NULL, SV *how=NULL)
  PPCODE:
    XPUSHs(&PL_sv_no);

UV
_refaddr(SV *sv, SV* dummy=NULL, SV *how=NULL)
  CODE:
    /* Simpler than Scalar::Util::refaddr, we don't bother to do get magic */
    if (!SvROK(sv)) XSRETURN_UNDEF;
    RETVAL = PTR2UV(SvRV(sv));
  OUTPUT:
    RETVAL

void
_error_line()
  PREINIT:
    int flags, line;
    const char *data, *file;
    char buf[256];
    unsigned long code;
    SV *result;
  PPCODE:
    TAINT_NOT;
    code = ERR_get_error_line_data(&file, &line, &data, &flags);
    if (!code) XSRETURN_UNDEF;
    ERR_error_string_n(code, buf, sizeof buf);
    result = newSVpvn("", 0);
    sv_2mortal(result);
    /* code is already in there as second element in the descr string */
    sv_catpvf(result, "descr=<%s>:file=\"%s\":line=%d:data=%s",
              buf, file, line, (flags & ERR_TXT_STRING) ? data : "");
    XPUSHs(result);

void
_clear_errors()
  PPCODE:
    ERR_clear_error();

void
context(SV *class)
  PREINIT:
    SV *object;
    const char *class_name;
  PPCODE:
    TAINT_NOT;
    class_name = c_class(class);
    object = sv_newmortal();
    sv_setref_pv(object, class_name, (void*) &utils);
    PUSHs(object);

void
taint(SV *arg, SV *taint=NULL)
  PPCODE:
    if (PL_tainting) {
        PUSHs(SvTAINTED(arg) ? &PL_sv_yes : &PL_sv_no);
        if (taint) {
            TAINT_NOT;
            if (SvTRUE(taint)) sv_taint(arg);
            else {
                if (PL_tainted)
                    croak("Turning tainting off using a tainted value");
                sv_untaint(arg);
            }
        }
    } else {
        if (SvTRUE(taint)) croak("Can't taint in a non tainted perl");
        PUSHs(&PL_sv_no);
    }

MODULE = WEC::SSL::Utils		PACKAGE = WEC::SSL

SV *
openssl_version()
  CODE:
    TAINT_NOT;
    RETVAL = newSVpvn(OPENSSL_VERSION_TEXT, sizeof("" OPENSSL_VERSION_TEXT)-1);
    SvUPGRADE(RETVAL, SVt_PVNV);
    SvIOK_on(RETVAL);
    SvIsUV_on(RETVAL);
    SvUVX(RETVAL) = OPENSSL_VERSION_NUMBER;
  OUTPUT:
    RETVAL

bool
feature_sensitive()
  CODE:
    RETVAL = SENSITIVE;
  OUTPUT:
    RETVAL

bool
feature_magic()
  CODE:
    RETVAL = DO_MAGIC;
  OUTPUT:
    RETVAL

bool
feature_taint()
  CODE:
    RETVAL = 1;
  OUTPUT:
    RETVAL

MODULE = WEC::SSL::Utils		PACKAGE = WEC::SSL::Error

void
reason(SV *error)
  PPCODE:
    TAINT_NOT;
    error = ERR_FETCH(error, "reason");
    PUSHs(error);

void
data(SV *error)
  PPCODE:
    TAINT_NOT;
    error = err_fetch(aTHX_ error, "data", 4, 0);
    PUSHs(error);

void
c_library(SV *error)
  PPCODE:
    TAINT_NOT;
    error = ERR_FETCH(error, "c_library");
    PUSHs(error);

void
c_function(SV *error)
  PPCODE:
    TAINT_NOT;
    error = ERR_FETCH(error, "c_function");
    PUSHs(error);

void
c_line(SV *error)
  PPCODE:
    TAINT_NOT;
    error = ERR_FETCH(error, "c_line");
    PUSHs(error);

void
c_file(SV *error)
  PPCODE:
    TAINT_NOT;
    error = ERR_FETCH(error, "c_file");
    PUSHs(error);

void
code(SV *error, SV* dummy=NULL, SV *how=NULL)
  PPCODE:
    TAINT_NOT;
    error = ERR_FETCH(error, "code");
    PUSHs(error);

void
error_string(SV *error, SV* dummy=NULL, SV *how=NULL)
  PREINIT:
    SV *result;
  PPCODE:
    TAINT_NOT;
    result = sv_newmortal();
    sv_setpvn(result, "", 0);
    error_string(aTHX_ result, error);
    PUSHs(result);

int
LIB_NONE()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_NONE;
  OUTPUT:
    RETVAL

int
LIB_SYS()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_SYS;
  OUTPUT:
    RETVAL

int
LIB_BN()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_BN;
  OUTPUT:
    RETVAL

int
LIB_RSA()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_RSA;
  OUTPUT:
    RETVAL

int
LIB_DH()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_DH;
  OUTPUT:
    RETVAL

int
LIB_EVP()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_EVP;
  OUTPUT:
    RETVAL

int
LIB_BUF()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_BUF;
  OUTPUT:
    RETVAL

int
LIB_OBJ()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_OBJ;
  OUTPUT:
    RETVAL

int
LIB_PEM()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_PEM;
  OUTPUT:
    RETVAL

int
LIB_DSA()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_DSA;
  OUTPUT:
    RETVAL

int
LIB_X509()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_X509;
  OUTPUT:
    RETVAL

int
LIB_ASN1()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_ASN1;
  OUTPUT:
    RETVAL

int
LIB_CONF()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_CONF;
  OUTPUT:
    RETVAL

int
LIB_CRYPTO()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_CRYPTO;
  OUTPUT:
    RETVAL

int
LIB_EC()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_EC;
  OUTPUT:
    RETVAL

int
LIB_SSL()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_SSL;
  OUTPUT:
    RETVAL

int
LIB_BIO()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_BIO;
  OUTPUT:
    RETVAL

int
LIB_PKCS7()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_PKCS7;
  OUTPUT:
    RETVAL

int
LIB_X509V3()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_X509V3;
  OUTPUT:
    RETVAL

int
LIB_PKCS12()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_PKCS12;
  OUTPUT:
    RETVAL

int
LIB_RAND()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_RAND;
  OUTPUT:
    RETVAL

int
LIB_DSO()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_DSO;
  OUTPUT:
    RETVAL

int
LIB_ENGINE()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_ENGINE;
  OUTPUT:
    RETVAL

int
LIB_OCSP()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_OCSP;
  OUTPUT:
    RETVAL

int
LIB_UI()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_UI;
  OUTPUT:
    RETVAL

int
LIB_COMP()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_COMP;
  OUTPUT:
    RETVAL

int
LIB_ECDSA()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_ECDSA;
  OUTPUT:
    RETVAL

int
LIB_ECDH()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_ECDH;
  OUTPUT:
    RETVAL

int
LIB_STORE()
  CODE:
    TAINT_NOT;
    RETVAL = ERR_LIB_STORE;
  OUTPUT:
    RETVAL

MODULE = WEC::SSL::Utils		PACKAGE = WEC::SSL::Errors

void
errors(SV *errors)
  PPCODE:
    TAINT_NOT;
    errors = ERRS_FETCH(errors, "errors");
    PUSHs(errors);

void
where(SV *errors)
  PPCODE:
    TAINT_NOT;
    errors = ERRS_FETCH(errors, "where");
    PUSHs(errors);

UV
line(SV *errors)
  PREINIT:
    const char *name, *end, *ptr;
    STRLEN len;
  CODE:
    TAINT_NOT;
    errors = ERRS_FETCH(errors, "where");
    name = SvPV(errors, len);
    while (len && name[len-1] == '\n') len--;
    while (len && name[len-1] == '.')  len--;
    ptr = end = &name[len];
    while (ptr > name && isDIGIT(ptr[-1])) ptr--;
    if (ptr == end) croak("No line number in error string '%"SVf"'", errors);
    RETVAL = 0;
    while (ptr < end) {
        if (RETVAL > ((UV) -10) / 10)
            croak("Overflow in line number in error string '%"SVf"'", errors);
        RETVAL = RETVAL * 10 + (*ptr++ - '0');
    }
  OUTPUT:
    RETVAL

SV *
file(SV *errors)
  PREINIT:
    const char *name, *end, *ptr;
    STRLEN len;
  CODE:
    TAINT_NOT;
    errors = ERRS_FETCH(errors, "where");
    name = SvPV(errors, len);
    while (len && name[len-1] == '\n') len--;
    while (len && name[len-1] == '.')  len--;
    ptr = end = &name[len];
    while (ptr > name && isDIGIT(ptr[-1])) ptr--;
    if (ptr == end) croak("No line number in error string '%"SVf"'", errors);
    end = ptr;
    while (ptr > name && isSPACE(ptr[-1])) ptr--;
    if (ptr == end)
        croak("No space before line number in error string '%"SVf"'", errors);
    if (ptr < name+4 ||
        toLOWER(ptr[-4]) != 'l' ||
        toLOWER(ptr[-3]) != 'i' ||
        toLOWER(ptr[-2]) != 'n' ||
        toLOWER(ptr[-1]) != 'e')
    croak("No 'line' before line number in error string '%"SVf"'", errors);
    ptr -= 4;
    end = ptr;
    while (ptr > name && isSPACE(ptr[-1])) ptr--;
    if (ptr == end)
        croak("No space before 'line' in error string '%"SVf"'", errors);
    end = ptr;

    while (name < end && isSPACE(*name)) name++;
    if (toLOWER(name[0]) != 'a' || toLOWER(name[1]) != 't' ||
        !isSPACE(name[2]))
        croak("Error string '%"SVf"' does not start with ' at '", errors);
    name += 3;
    while (name < end && isSPACE(*name)) name++;
    if (end == name) croak("Error string '%"SVf"' has no filename", errors);

    RETVAL = newSVpvn(name, end-name);
    if (SvUTF8(errors)) SvUTF8_on(RETVAL);
  OUTPUT:
    RETVAL

void
error_string(SV *errors, SV* dummy=NULL, SV *how=NULL)
  PREINIT:
    HV *err_hv;
    AV *err_av;
    SV **ptr;
    I32 i;
    SV *result;
    UV code;
  PPCODE:
    TAINT_NOT;
    if (!sv_derived_from(errors, PACKAGE_BASE "::Errors")) {
        if (!SvOK(errors)) croak("errors is undefined");
        croak("errors is not of type " PACKAGE_BASE "::Errors");
    }
    if (!SvROK(errors)) croak("errors is not a reference");
    err_hv = (HV *) SvRV(errors);
    if (SvTYPE(err_hv) != SVt_PVHV) croak("errors is not a HASH reference");
    ptr = hv_fetch(err_hv, "errors", 6, 0);
    if (!ptr) croak("No errors entry");
    if (!SvROK(*ptr))croak("errors entry is not a reference");
    err_av = (AV *) SvRV(*ptr);
    if (SvTYPE(err_av) != SVt_PVAV)
        croak("errors entry is is not an ARRAY reference");
    result = sv_newmortal();
    sv_setpvn(result, "", 0);
    for (i=0; i<= av_len(err_av); i++) {
        ptr = av_fetch(err_av, i, 0);
        if (!ptr) croak("Empty error in error list");
        if (i != 0) sv_catpvn(result, ", ", 2);
        error_string(aTHX_ result, *ptr);
    }
    if (i == 0) croak("No errors in sequence");
    ptr = hv_fetch(err_hv, "where", 5, 0);
    if (!ptr) croak("No where entry");
    sv_catsv(result, *ptr);
    PUSHs(result);

BOOT:
    SSL_load_error_strings();

    utils.api_version	= UTILS_API_VERSION;
    utils.not_a_number	= not_a_number;
    utils.get_int	= get_int;
    utils.get_long	= get_long;
    utils.get_UV	= get_UV;
    utils.c_sv		= c_sv;
    utils.c_object	= c_object;
    utils.low_eq	= low_eq;
    utils.sv_bytes	= sv_bytes;
    utils.sv_canonical	= sv_canonical;
    utils.sv_file	= sv_file;
    utils.utf8_copy	= utf8_copy;
    utils.sv_to_bio	= sv_to_bio;
    utils.c_ascii	= c_ascii;
    utils.ref_tainted	= ref_tainted;
    utils.load_engines	= load_engines;
    utils.digest_by_name= digest_by_name;
    utils.cipher_by_name= cipher_by_name;
    utils.engine_by_name= engine_by_name;
    utils.try_digest	= try_digest;
    utils.try_cipher	= try_cipher;
    utils.try_engine	= try_engine;
    utils.crypto_croak	= crypto_croak;
