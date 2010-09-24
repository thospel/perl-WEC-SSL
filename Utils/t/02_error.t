#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 02_error.t'
#########################
use strict;
use warnings;

our $VERSION = "1.000";

BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Error
;
use WEC::SSL::BigInt
;

my @methods = qw(LIB_NONE LIB_SYS LIB_BN LIB_RSA LIB_DH LIB_EVP LIB_BUF LIB_OBJ
                 LIB_PEM LIB_DSA LIB_X509 LIB_ASN1 LIB_CONF LIB_CRYPTO LIB_EC
                 LIB_SSL LIB_BIO LIB_PKCS7 LIB_X509V3 LIB_PKCS12 LIB_RAND
                 LIB_DSO LIB_ENGINE LIB_OCSP LIB_UI LIB_COMP LIB_ECDSA
                 LIB_ECDH LIB_STORE);
# Check exports
can_ok("WEC::SSL::Error", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}
"WEC::SSL::Error"->import(@methods);
can_ok(__PACKAGE__, @methods);

eval { WEC::SSL::BigInt->from_mpi("") };
if (!$@) {
    fail("No error from division by zero");
    exit;
}
if (!UNIVERSAL::isa($@, "WEC::SSL::Errors")) {
    fail("Error from invalid MPI ($@) is not of class WEC::SSL::Errors");
    exit;
}
my $errors = $@->errors;
if (@$errors != 1) {
    fail("Invalid MPI lead to " . @$errors . " errors");
    exit;
}
my $error = $errors->[0];
if (!UNIVERSAL::isa($error, "WEC::SSL::Error")) {
    fail("Error from invalid MPI ($error) is not of class WEC::SSL::Error");
    exit;
}
is($error->code, 0x0307006a);
is("" . $error->reason, "invalid length");
is(0  + $error->reason, 0x06a);
is("" . $error->c_function, "BN_mpi2bn");
is(0  + $error->c_function, 0x70);
is("" . $error->c_library, "bignum routines");
is(0  + $error->c_library, 0x03);
is($error->data, undef);
like($error->c_file, qr/\bbn_mpi\.c/i);
ok($error->c_line =~ /^\d+$/);
is("" . $error->error_string, "invalid length");
is(0  + $error->error_string, $error->code);
is("$error", "invalid length");
is(sprintf("%d", $error), $error->code);
ok($error);
