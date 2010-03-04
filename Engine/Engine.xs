#include "wec_ssl.h"
#include <string.h>

INIT_UTILS

#define NEW_CLASS(eng, fl, object, class) STMT_START {	\
    Newx(engine, 1, struct wec_engine);	\
    engine->e = eng;					\
    engine->flags = fl;					\
    (object) = sv_newmortal();				\
    sv_setref_pv(object, class, (void*) (engine));	\
    SvTAINT(object);					\
} STMT_END

/* Next is a copy from eng_int.h, only used by the rederence count accessors
   And these are purely for developer debugging, not part of the documented
   interface. So if they don't work anymore, or drift from the actually used
   OpenSSL version, just delete it */
struct engine_st {
    const char *id;
    const char *name;
    const RSA_METHOD *rsa_meth;
    const DSA_METHOD *dsa_meth;
    const DH_METHOD *dh_meth;
    const ECDH_METHOD *ecdh_meth;
    const ECDSA_METHOD *ecdsa_meth;
    const RAND_METHOD *rand_meth;
    const STORE_METHOD *store_meth;
    /* Cipher handling is via this callback */
    ENGINE_CIPHERS_PTR ciphers;
    /* Digest handling is via this callback */
    ENGINE_DIGESTS_PTR digests;

    ENGINE_GEN_INT_FUNC_PTR	destroy;

    ENGINE_GEN_INT_FUNC_PTR init;
    ENGINE_GEN_INT_FUNC_PTR finish;
    ENGINE_CTRL_FUNC_PTR ctrl;
    ENGINE_LOAD_KEY_PTR load_privkey;
    ENGINE_LOAD_KEY_PTR load_pubkey;

    const ENGINE_CMD_DEFN *cmd_defns;
    int flags;
    /* reference count on the structure itself */
    int struct_ref;
    /* reference count on usability of the engine type. NB: This
     * controls the loading and initialisation of any functionlity
     * required by this engine, whereas the previous count is
     * simply to cope with (de)allocation of this structure. Hence,
     * running_ref <= struct_ref at all times. */
    int funct_ref;
    /* A place to store per-ENGINE data */
    CRYPTO_EX_DATA ex_data;
    /* Used to maintain the linked-list of engines. */
    struct engine_st *prev;
    struct engine_st *next;
};

MODULE = WEC::SSL::Engine		PACKAGE = WEC::SSL::Engine
PROTOTYPES: ENABLE

void
by_name(SV *class, SV *name)
  PREINIT:
    wec_engine engine;
    SV *object;
    ENGINE *e;
    const char *class_name;
  PPCODE:
    TAINT_NOT;
    e = ENGINE_BY_NAME(name);
    if (!e) CRYPTO_CROAK("Engine '%"SVf"' is not available", name);
    class_name = C_CLASS(class);
    NEW_CLASS(e, ENGINE_NEEDS_FREE, object, class_name);
    PUSHs(object);

void
RSA(SV *class)
  ALIAS:
    WEC::SSL::Engine::DSA   = 1
    WEC::SSL::Engine::ECDH  = 2
    WEC::SSL::Engine::ECDSA = 3
    WEC::SSL::Engine::DH    = 4
    WEC::SSL::Engine::RAND  = 5
  PREINIT:
    const char *class_name;
    wec_engine engine;
    SV *object;
    ENGINE *e;
  PPCODE:
    TAINT_NOT;
    class_name = C_CLASS(class);
    switch(ix) {
      case 1:
        e = ENGINE_get_default_DSA();
        if (!e) CRYPTO_CROAK("DSA Engine is not available");
        break;
      case 2:
        e = ENGINE_get_default_ECDH();
        if (!e) CRYPTO_CROAK("ECDH Engine is not available");
        break;
      case 3:
        e = ENGINE_get_default_ECDSA();
        if (!e) CRYPTO_CROAK("ECDSA Engine is not available");
        break;
      case 4:
        e = ENGINE_get_default_DH();
        if (!e) CRYPTO_CROAK("DH Engine is not available");
        break;
      case 5:
        e = ENGINE_get_default_RAND();
        if (!e) CRYPTO_CROAK("RAND Engine is not available");
        break;
      default:
        e = ENGINE_get_default_RSA();
        if (!e) CRYPTO_CROAK("RSA Engine is not available");
        break;
    }
    NEW_CLASS(e, ENGINE_NEEDS_FINISH, object, class_name);
    PUSHs(object);

void
for_RSA(SV *engine)
  PREINIT:
    wec_engine eng;
    int rc;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_RSA'");
    rc = ENGINE_set_default_RSA(eng->e);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for RSA");

void
for_DSA(SV *engine)
  PREINIT:
    wec_engine eng;
    int rc;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_DSA'");
    rc = ENGINE_set_default_DSA(eng->e);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for DSA");

void
for_ECDH(SV *engine)
  PREINIT:
    wec_engine eng;
    int rc;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_ECDH'");
    rc = ENGINE_set_default_ECDH(eng->e);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for ECDH");

void
for_ECDSA(SV *engine)
  PREINIT:
    wec_engine eng;
    int rc;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_ECDSA'");
    rc = ENGINE_set_default_ECDSA(eng->e);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for ECDSA");

void
for_DH(SV *engine)
  PREINIT:
    wec_engine eng;
    int rc;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_DH'");
    rc = ENGINE_set_default_DH(eng->e);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for DH");

void
for_RAND(SV *engine)
  PREINIT:
    wec_engine eng;
    int rc;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_RAND'");
    rc = ENGINE_set_default_RAND(eng->e);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for RAND");

void
ciphers(SV *class, SV *nid)
  ALIAS:
    WEC::SSL::Engine::digests = 1
  PREINIT:
    wec_engine engine;
    const char *class_name;
    SV *object;
    int id;
    ENGINE *e;
  PPCODE:
    TAINT_NOT;
    class_name = C_CLASS(class);
    id = GET_INT(nid, "nid");
    switch(ix) {
      case 1:
        e = ENGINE_get_digest_engine(id);
        if (!e) CRYPTO_CROAK("digest engine %d is not available", id);
        break;
      default:
        e = ENGINE_get_digest_engine(id);
        if (!e) CRYPTO_CROAK("cipher engine %d is not available", nid);
        break;
    }

    NEW_CLASS(e, ENGINE_NEEDS_FREE, object, class_name);
    PUSHs(object);

void
for_ciphers(SV *engine)
  PREINIT:
    int rc;
    wec_engine eng;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_ciphers'");
    rc = ENGINE_set_default_ciphers(eng->e);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for ciphers");

void
for_digests(SV *engine)
  PREINIT:
    int rc;
    wec_engine eng;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_digests'");
    rc = ENGINE_set_default_digests(eng->e);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for digests");

void
for_all(SV *engine)
  PREINIT:
    int rc;
    wec_engine eng;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'for_all'");
    rc = ENGINE_set_default(eng->e, ENGINE_METHOD_ALL);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for everything");

void
for(SV *engine, SV *sv_string)
  PREINIT:
    int rc;
    const char *string;
    wec_engine eng;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    /* Check if we have a plain C-string as engine name */
    string = C_ASCII(sv_string, "Operations string");
    TAINT_PROPER("'for'");
    rc = ENGINE_set_default_string(eng->e, string);
    if (!rc) CRYPTO_CROAK("Could not set engine as default for the given operations");

int
flags(SV *engine, SV *flags=NULL)
  PREINIT:
    wec_engine eng;
    int rc, iflags;
  CODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    RETVAL = ENGINE_get_flags(eng->e);
    if (flags) {
        iflags = GET_INT(flags, "flags");
        TAINT_PROPER("'flags'");
        rc = ENGINE_set_flags(eng->e, iflags);
        if (!rc) CRYPTO_CROAK("Could not set engine flags");
    }
  OUTPUT:
    RETVAL

void
initialize(SV *engine)
  PREINIT:
    int rc;
    wec_engine eng;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    TAINT_PROPER("'initialize'");
    if (eng->flags & ENGINE_NEEDS_FINISH) croak("Engine already initialized");
    rc = ENGINE_init(eng->e);
    if (!rc) CRYPTO_CROAK("Could not initialize engine");
    eng->flags |= ENGINE_NEEDS_FINISH;

void
initialized(SV *engine)
  PREINIT:
    wec_engine eng;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    PUSHs(eng->flags & ENGINE_NEEDS_FINISH ? &PL_sv_yes : &PL_sv_no);

const char *
name(SV *engine)
  PREINIT:
    wec_engine eng;
  CODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    RETVAL = ENGINE_get_id(eng->e);
  OUTPUT:
    RETVAL

const char *
description(SV *engine)
  PREINIT:
    wec_engine eng;
  CODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    RETVAL = ENGINE_get_name(eng->e);
  OUTPUT:
    RETVAL

void
has_control_commands(wec_engine engine)
  PREINIT:
    int ctrl_exists;
  PPCODE:
    ctrl_exists =
        ENGINE_ctrl(engine->e, ENGINE_CTRL_HAS_CTRL_FUNCTION, 0, 0, 0);
    if (ctrl_exists < 0) CRYPTO_CROAK("ENGINE_ctrl error");
    PUSHs(ctrl_exists ? &PL_sv_yes : &PL_sv_no);

int
first_control_command(SV *engine)
  PREINIT:
    wec_engine eng;
  CODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    RETVAL = ENGINE_ctrl(eng->e, ENGINE_CTRL_GET_FIRST_CMD_TYPE, 0, 0, 0);
    if (RETVAL < 0) CRYPTO_CROAK("ENGINE_ctrl error");
  OUTPUT:
    RETVAL

int
next_control_command(SV *engine, SV *id)
  PREINIT:
    wec_engine eng;
    int cmd;
  CODE:
    TAINT_NOT;
    cmd = GET_INT(id, "id");
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    RETVAL = ENGINE_ctrl(eng->e, ENGINE_CTRL_GET_NEXT_CMD_TYPE, cmd, 0, 0);
    if (RETVAL < 0) CRYPTO_CROAK("ENGINE_ctrl error");
  OUTPUT:
    RETVAL

void
control_command_name_from_id(SV *engine, SV *id)
  PREINIT:
    wec_engine eng;
    int rc, cmd, length;
    SV *object;
    char *str;
    STRLEN dummy_len;
  PPCODE:
    TAINT_NOT;
    cmd = GET_INT(id, "id");
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    length = ENGINE_ctrl(eng->e, ENGINE_CTRL_GET_NAME_LEN_FROM_CMD, cmd, 0, 0);
    if (length <= 0) CRYPTO_CROAK("ENGINE_ctrl error GET_NAME_LEN_FROM_CMD");
    object = newSV(length);
    sv_2mortal(object);
    PUSHs(object);
    sv_setpvn(object, "", 0);
    str = SvPV(object, dummy_len);
    str[length] = 1;
    rc = ENGINE_ctrl(eng->e, ENGINE_CTRL_GET_NAME_FROM_CMD, cmd, str, 0);
    if (rc != length) {
        if (rc <= 0) CRYPTO_CROAK("ENGINE_ctrl error GET_NAME_FROM_CMD");
        croak("Assertion: Unexpected length");
    }
    if (str[length])
        croak("Assertion: string returned by OpenSSL not \\0 terminted");
    SvCUR_set(object, length);

int
control_command_flags_from_id(SV *engine, SV *id)
  PREINIT:
    wec_engine eng;
    int cmd;
  CODE:
    TAINT_NOT;
    cmd = GET_INT(id, "id");
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    RETVAL = ENGINE_ctrl(eng->e, ENGINE_CTRL_GET_CMD_FLAGS, cmd, 0, 0);
    if (RETVAL < 0)
        CRYPTO_CROAK("ENGINE_ctrl error ENGINE_CTRL_GET_CMD_FLAGS");
  OUTPUT:
    RETVAL

void
control_command_description_from_id(SV *engine, SV *id)
  PREINIT:
    wec_engine eng;
    int rc, cmd, length;
    SV *object;
    char *str;
    STRLEN dummy_len;
  PPCODE:
    TAINT_NOT;
    cmd = GET_INT(id, "id");
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    length = ENGINE_ctrl(eng->e, ENGINE_CTRL_GET_DESC_LEN_FROM_CMD, cmd, 0, 0);
    if (length <= 0) CRYPTO_CROAK("ENGINE_ctrl error GET_DESC_LEN_FROM_CMD");
    object = newSV(length);
    sv_2mortal(object);
    PUSHs(object);
    sv_setpvn(object, "", 0);
    str = SvPV(object, dummy_len);
    str[length] = 1;
    rc = ENGINE_ctrl(eng->e, ENGINE_CTRL_GET_DESC_FROM_CMD, cmd, str, 0);
    if (rc != length) {
        if (rc <= 0) CRYPTO_CROAK("ENGINE_ctrl error GET_DESC_FROM_CMD");
        croak("Assertion: Unexpected length");
    }
    if (str[length])
        croak("Assertion: string returned by OpenSSL not \\0 terminted");
    SvCUR_set(object, length);

void
control_command(SV *engine, SV *sv_name, SV *sv_value=NULL)
  PREINIT:
    const char *name, *value;
    int rc;
    wec_engine eng;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    name  = C_ASCII(sv_name,  "Control command name");
    value = sv_value ? C_ASCII(sv_value, "Control command value") : NULL ;
    TAINT_PROPER("'control_command'");
    rc = ENGINE_ctrl_cmd_string(eng->e, name, value, 0);
    if (!rc) CRYPTO_CROAK("Could not execute control command '%s'", name);

void
try_control_command(SV *engine, SV *sv_name, SV *sv_value)
  PREINIT:
    const char *name, *value;
    int rc;
    wec_engine eng;
  PPCODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    name  = C_ASCII(sv_name,  "Control command name");
    value = C_ASCII(sv_value, "Control command value");
    TAINT_PROPER("'try_control_command'");
    rc = ENGINE_ctrl_cmd_string(eng->e, name, value, 1);
    if (!rc) CRYPTO_CROAK("Could not execute supported control command '%s'", name);

void
taint(SV *arg, SV *taint=NULL)
  PPCODE:
    REF_TAINTED(arg, taint, PACKAGE_BASE "::Engine", "arg");

int
_structure_refcount(SV *engine)
  ALIAS:
    WEC::SSL::Engine::_function_refcount = 1
  PREINIT:
    wec_engine eng;
  CODE:
    TAINT_NOT;
    eng = C_OBJECT(engine, PACKAGE_BASE "::Engine", "engine");
    RETVAL = ix ?
        ((struct engine_st *)eng->e)->funct_ref :
        ((struct engine_st *)eng->e)->struct_ref;
  OUTPUT:
    RETVAL

void
DESTROY(wec_engine engine)
  PPCODE:
    if (engine->e) {
        if (engine->flags & ENGINE_NEEDS_FINISH) ENGINE_finish(engine->e);
        if (engine->flags & ENGINE_NEEDS_FREE) ENGINE_free(engine->e);
    }
    Safefree(engine);

int
METHOD_RSA()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_RSA;
  OUTPUT:
    RETVAL

int
METHOD_DSA()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_DSA;
  OUTPUT:
    RETVAL

int
METHOD_DH()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_DH;
  OUTPUT:
    RETVAL

int
METHOD_RAND()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_RAND;
  OUTPUT:
    RETVAL

int
METHOD_ECDH()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_ECDH;
  OUTPUT:
    RETVAL

int
METHOD_ECDSA()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_ECDSA;
  OUTPUT:
    RETVAL

int
METHOD_CIPHERS()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_CIPHERS;
  OUTPUT:
    RETVAL

int
METHOD_DIGESTS()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_DIGESTS;
  OUTPUT:
    RETVAL

int
METHOD_STORE()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_STORE;
  OUTPUT:
    RETVAL

int
METHOD_ALL()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_ALL;
  OUTPUT:
    RETVAL

int
METHOD_NONE()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_METHOD_NONE;
  OUTPUT:
    RETVAL

int
FLAGS_MALLOCED()
  CODE:
    TAINT_NOT;
#ifdef ENGINE_FLAGS_MALLOCED
    RETVAL = ENGINE_FLAGS_MALLOCED;
#else
    croak(PACKAGE_BASE "::Engine::FLAGS_MALLOCED not defined in this OpenSSL library");
#endif
  OUTPUT:
    RETVAL

int
FLAGS_MANUAL_CMD_CTRL()
  CODE:
    TAINT_NOT;
#ifdef ENGINE_FLAGS_MANUAL_CMD_CTRL
    RETVAL = ENGINE_FLAGS_MANUAL_CMD_CTRL;
#else
    croak(PACKAGE_BASE "::Engine::FLAGS_MANUAL_CMD_CTRL not defined in this OpenSSL library");
#endif
  OUTPUT:
    RETVAL

int
FLAGS_BY_ID_COPY()
  CODE:
    TAINT_NOT;
#ifdef ENGINE_FLAGS_BY_ID_COPY
    RETVAL = ENGINE_FLAGS_BY_ID_COPY;
#else
    croak(PACKAGE_BASE "::Engine::FLAGS_BY_ID_COPY not defined in this OpenSSL library");
#endif
  OUTPUT:
    RETVAL

int
CMD_BASE()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CMD_BASE;
  OUTPUT:
    RETVAL

int
CTRL_HAS_CTRL_FUNCTION()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_HAS_CTRL_FUNCTION;
  OUTPUT:
    RETVAL

int
CTRL_GET_FIRST_CMD_TYPE()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_GET_FIRST_CMD_TYPE;
  OUTPUT:
    RETVAL

int
CTRL_GET_NEXT_CMD_TYPE()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_GET_NEXT_CMD_TYPE;
  OUTPUT:
    RETVAL

int
CTRL_GET_CMD_FROM_NAME()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_GET_CMD_FROM_NAME;
  OUTPUT:
    RETVAL

int
CTRL_GET_NAME_LEN_FROM_CMD()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_GET_NAME_LEN_FROM_CMD;
  OUTPUT:
    RETVAL

int
CTRL_GET_NAME_FROM_CMD()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_GET_NAME_FROM_CMD;
  OUTPUT:
    RETVAL

int
CTRL_GET_DESC_LEN_FROM_CMD()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_GET_DESC_LEN_FROM_CMD;
  OUTPUT:
    RETVAL

int
CTRL_GET_DESC_FROM_CMD()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_GET_DESC_FROM_CMD;
  OUTPUT:
    RETVAL

int
CTRL_GET_CMD_FLAGS()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CTRL_GET_CMD_FLAGS;
  OUTPUT:
    RETVAL

int
CMD_FLAG_NUMERIC()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CMD_FLAG_NUMERIC;
  OUTPUT:
    RETVAL

int
CMD_FLAG_STRING()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CMD_FLAG_STRING;
  OUTPUT:
    RETVAL

int
CMD_FLAG_NO_INPUT()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CMD_FLAG_NO_INPUT;
  OUTPUT:
    RETVAL

int
CMD_FLAG_INTERNAL()
  CODE:
    TAINT_NOT;
    RETVAL = ENGINE_CMD_FLAG_INTERNAL;
  OUTPUT:
    RETVAL

MODULE = WEC::SSL::Engine		PACKAGE = WEC::SSL::EngineList

void
TIEHASH(SV *class)
  PREINIT:
    const char *class_name;
    SV *object;
  PPCODE:
    TAINT_NOT;
    class_name = C_CLASS(class);
    object = sv_newmortal();
    sv_setiv(newSVrv(object, class_name), 0);
    PUSHs(object);

void
FIRSTKEY(SV *self)
  PREINIT:
    ENGINE *e, *e_old;
    const char *name;
    SV *sv, *result;
    IV address;
  PPCODE:

    TAINT_NOT;
    /* Load builtin engines */
    LOAD_ENGINES();

    SvGETMAGIC(self);
    sv = C_SV(self, PACKAGE_BASE "::EngineList", "self");
    address = SvIV(sv);

    e = ENGINE_get_first();
    if (e) {
        name = ENGINE_get_id(e);
        if (!name) {
            ENGINE_free(e);
            croak("Assert: engine without id");
        }

        result = newSVpv(name, 0);
        sv_2mortal(result);
        PUSHs(result);
    } else PUSHs(sv_newmortal());

    if (address) {
        e_old = INT2PTR(ENGINE *, address);
        ENGINE_free(e_old);
    }
    sv_setiv(sv, PTR2IV(e));

void
NEXTKEY(SV *self, SV *name)
  PREINIT:
    ENGINE *e, *e_old;
    const char *e_name;
    const U8 *str;
    SV *sv, *result;
    STRLEN l, len;
    IV address;
  PPCODE:
    TAINT_NOT;
    /* Load builtin engines */
    LOAD_ENGINES();

    SvGETMAGIC(self);
    sv = C_SV(self, PACKAGE_BASE "::EngineList", "self");
    address = SvIV(sv);

    str = SvPV(name, len);
    if (str[len]) croak("Assert: perl string does not end on \\0");
    if (SvUTF8(name)) {
        for (l=0; l<len; l++)
            if (!UNI_IS_INVARIANT(str[len]) || str[len] == 0) XSRETURN_UNDEF;
    } else if (memchr(str, 0, len)) XSRETURN_UNDEF;

    if (address) {
        e = INT2PTR(ENGINE *, address);
        e_name = ENGINE_get_id(e);
        if (!e_name) {
            ENGINE_free(e);
            croak("Assert: engine without id");
        }
        if (strEQ(e_name, str)) goto FOUND;
    }
    for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
        e_name = ENGINE_get_id(e);
        if (!e_name) {
            ENGINE_free(e);
            croak("Assert: engine without id");
        }
        if (strEQ(e_name, str)) {
            if (address) {
                e_old = INT2PTR(ENGINE *, address);
                ENGINE_free(e_old);
            }
          FOUND:
            e = ENGINE_get_next(e);
            sv_setiv(sv, PTR2IV(e));
            if (!e) break;
            e_name = ENGINE_get_id(e);
            if (!e_name) croak("Assert: engine without id");

            result = newSVpv(e_name, 0);
            sv_2mortal(result);
            PUSHs(result);
            XSRETURN(1);
        }
    }
    PUSHs(sv_newmortal());

void
FETCH(SV *self, SV *name)
  ALIAS:
    WEC::SSL::EngineList::EXISTS = 1
  PREINIT:
    wec_engine engine;
    SV *object;
    ENGINE *e;
    STRLEN l, len;
    const U8 *str;
  PPCODE:
    TAINT_NOT;

    SvGETMAGIC(self);
    C_SV(self, PACKAGE_BASE "::EngineList", "self");

    str = SvPV(name, len);
    if (str[len]) croak("Assert: perl string does not end on \\0");
    if (SvUTF8(name)) {
        for (l=0; l<len; l++)
            if (!UNI_IS_INVARIANT(str[len]) || str[len] == 0) XSRETURN_UNDEF;
    } else if (memchr(str, 0, len)) XSRETURN_UNDEF;

    e = ENGINE_BY_NAME(name);
    if (!e) XSRETURN_UNDEF;
    if (ix == 1) XSRETURN_YES;

    NEW_CLASS(e, ENGINE_NEEDS_FREE, object, PACKAGE_BASE "::Engine");
    PUSHs(object);

void
DESTROY(SV *self)
  PREINIT:
    SV *object;
    IV address;
    ENGINE *e;
  PPCODE:
    SvGETMAGIC(self);
    object = C_SV(self, PACKAGE_BASE "::EngineList", "self");
    address = SvIV(object);
    if (address) {
        e = INT2PTR(ENGINE *, address);
        ENGINE_free(e);
    }

BOOT:
    init_utils();
