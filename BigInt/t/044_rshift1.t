#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 044_rshift1.t'
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

my @methods = qw(rshift1);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);



















# rshift1(-3) = -2
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::rshift1(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(!tainted($result));
}

# rshift1(-2) = -1
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::rshift1(-2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!tainted($result));
}

# rshift1(-1) = -1
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::rshift1(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!tainted($result));
}

# rshift1(0) = 0
$arg = Big->new(0);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::rshift1(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# rshift1(1) = 0
$arg = Big->new(1);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::rshift1(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# rshift1(2) = 1
$arg = Big->new(2);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::rshift1(2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!tainted($result));
}

# rshift1(3) = 1
$arg = Big->new(3);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::rshift1(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!tainted($result));
}

# rshift1(9) = 4
$arg = Big->new(9);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::rshift1(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok(!tainted($result));
}

# rshift1(-9) = -5
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::rshift1(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -5);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -5);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -5);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -5);
    ok(!tainted($result));
}

# rshift1(12) = 6
$arg = Big->new(12);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::rshift1(12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(!tainted($result));
}

# rshift1(-12) = -6
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::rshift1(-12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -6);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -6);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -6);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -6);
    ok(!tainted($result));
}

# rshift1(581) = 290
$arg = Big->new(581);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 290);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 290);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 290);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::rshift1(581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 290);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 290);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 290);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 290);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 290);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 290);
    ok(!tainted($result));
}

# rshift1(-581) = -291
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::rshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -291);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::rshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -291);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::rshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -291);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::rshift1(-581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -291);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->rshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -291);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -291);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -291);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -291);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::rshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -291);
    ok(!tainted($result));
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
