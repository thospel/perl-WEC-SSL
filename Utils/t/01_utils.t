#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 01_utils.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Utils;
use WEC::SSL::BigInt;

can_ok("WEC::SSL::Utils", "context");

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
# These must work even without loading WEC::SSL::Error
my $code = 0x0307006a;
is("$error", "invalid length");
is(sprintf("%d", $error), $code);
ok($error);
