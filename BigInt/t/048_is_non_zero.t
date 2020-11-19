#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 048_is_non_zero.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL qw(feature_sensitive feature_taint);
use WEC::SSL::BigInt;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(is_non_zero);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);



















# is_non_zero(-3) = 1
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::is_non_zero(-3);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(-2) = 1
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::is_non_zero(-2);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(-1) = 1
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::is_non_zero(-1);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(0) = ""
$arg = Big->new(0);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, "");
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::is_non_zero(0);
is(ref($result), "");
is($result, "");
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, "");

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, "");
}

# is_non_zero(1) = 1
$arg = Big->new(1);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::is_non_zero(1);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(2) = 1
$arg = Big->new(2);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::is_non_zero(2);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(3) = 1
$arg = Big->new(3);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::is_non_zero(3);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(9) = 1
$arg = Big->new(9);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::is_non_zero(9);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(-9) = 1
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::is_non_zero(-9);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(12) = 1
$arg = Big->new(12);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::is_non_zero(12);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(-12) = 1
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::is_non_zero(-12);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(581) = 1
$arg = Big->new(581);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::is_non_zero(581);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_non_zero(-581) = 1
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::is_non_zero($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_non_zero($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_non_zero($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::is_non_zero(-581);
is(ref($result), "");
is($result, 1);
$result = $arg->is_non_zero;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
}

# Check operation under sensitivity
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::is_non_zero($arg);
    is(ref($result), "");
    is($result, 1);
    ok(!tainted($result));
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
