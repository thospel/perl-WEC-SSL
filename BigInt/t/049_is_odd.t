#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 049_is_odd.t'
#########################
## no critic (ProhibitUselessNoCritic ProhibitMagicNumbers)
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

my @methods = qw(is_odd);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);

# is_odd(-3) = 1
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::is_odd(-3);
is(ref($result), "");
is($result, 1);
$result = $arg->is_odd;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_odd(-2) = ""
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, "");
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::is_odd(-2);
is(ref($result), "");
is($result, "");
$result = $arg->is_odd;
is(ref($result), "");
is($result, "");
# Check operation under sensitivity
 SKIP: {
     skip "Compiled without sensitive support" if !feature_sensitive();

     $arg->sensitive(1);
     $result = WEC::SSL::BigInt::is_odd($arg);
     is(ref($result), "");
     is($result, "");

     $arg->sensitive(0);
     $result = WEC::SSL::BigInt::is_odd($arg);
     is(ref($result), "");
     is($result, "");
}

# is_odd(-1) = 1
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::is_odd(-1);
is(ref($result), "");
is($result, 1);
$result = $arg->is_odd;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_odd(0) = ""
$arg = Big->new(0);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, "");
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::is_odd(0);
is(ref($result), "");
is($result, "");
$result = $arg->is_odd;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, "");

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, "");
}

# is_odd(1) = 1
$arg = Big->new(1);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::is_odd(1);
is(ref($result), "");
is($result, 1);
$result = $arg->is_odd;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_odd(2) = ""
$arg = Big->new(2);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, "");
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::is_odd(2);
is(ref($result), "");
is($result, "");
$result = $arg->is_odd;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, "");

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, "");
}

# is_odd(3) = 1
$arg = Big->new(3);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::is_odd(3);
is(ref($result), "");
is($result, 1);
$result = $arg->is_odd;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_odd(9) = 1
$arg = Big->new(9);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::is_odd(9);
is(ref($result), "");
is($result, 1);
$result = $arg->is_odd;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_odd(-9) = 1
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::is_odd(-9);
is(ref($result), "");
is($result, 1);
$result = $arg->is_odd;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_odd(12) = ""
$arg = Big->new(12);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, "");
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::is_odd(12);
is(ref($result), "");
is($result, "");
$result = $arg->is_odd;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, "");

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, "");
}

# is_odd(-12) = ""
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, "");
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::is_odd(-12);
is(ref($result), "");
is($result, "");
$result = $arg->is_odd;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, "");

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, "");
}

# is_odd(581) = 1
$arg = Big->new(581);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::is_odd(581);
is(ref($result), "");
is($result, 1);
$result = $arg->is_odd;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);
}

# is_odd(-581) = 1
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::is_odd($arg);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::is_odd($arg, undef, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::is_odd($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::is_odd(-581);
is(ref($result), "");
is($result, 1);
$result = $arg->is_odd;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, 1);
}

SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    my $taint = substr("$0$^X", 0, 0);

    $arg = Big->new(-581 . $taint);
    is(tainted($arg), 1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, !!1);
    is(tainted($result), 1);

    $arg = Big->new(-580 . $taint);
    is(tainted($arg), 1);
    $result = WEC::SSL::BigInt::is_odd($arg);
    is(ref($result), "");
    is($result, !!0);
    is(tainted($result), 1);
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
