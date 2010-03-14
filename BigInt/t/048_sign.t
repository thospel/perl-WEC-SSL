#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 048_sign.t'
#########################
our $VERSION = "1.000";

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL qw(feature_sensitive feature_taint);
use WEC::SSL::BigInt;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(sign);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);



















# sign(-3) = -1
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::sign(-3);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(!tainted($result));
}

# sign(-2) = -1
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::sign(-2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(!tainted($result));
}

# sign(-1) = -1
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::sign(-1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(!tainted($result));
}

# sign(0) = 0
$arg = Big->new(0);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::sign(0);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 0);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 0);
    ok(!tainted($result));
}

# sign(1) = 1
$arg = Big->new(1);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::sign(1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(!tainted($result));
}

# sign(2) = 1
$arg = Big->new(2);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::sign(2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(!tainted($result));
}

# sign(3) = 1
$arg = Big->new(3);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::sign(3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(!tainted($result));
}

# sign(9) = 1
$arg = Big->new(9);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::sign(9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(!tainted($result));
}

# sign(-9) = -1
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::sign(-9);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(!tainted($result));
}

# sign(12) = 1
$arg = Big->new(12);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::sign(12);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(!tainted($result));
}

# sign(-12) = -1
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::sign(-12);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(!tainted($result));
}

# sign(581) = 1
$arg = Big->new(581);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::sign(581);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, 1);
    ok(!tainted($result));
}

# sign(-581) = -1
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::sign($arg);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::sign($arg, undef, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::sign($tmp, undef, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::sign(-581);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg->sign;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::sign($arg);
    is(ref($result), "");
    is($result, -1);
    ok(!tainted($result));
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
