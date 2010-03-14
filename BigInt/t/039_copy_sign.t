#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 039_copy_sign.t'
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

my @methods = qw(copy_sign);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# copy_sign(-1, -1) = -1
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::copy_sign(-1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!tainted($result));
}

# copy_sign(-1, 0) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::copy_sign(-1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# copy_sign(-1, 1) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::copy_sign(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!tainted($result));
}

# copy_sign(0, -1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::copy_sign(0, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# copy_sign(0, 0) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::copy_sign(0, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# copy_sign(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::copy_sign(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# copy_sign(1, -1) = -1
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::copy_sign(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!tainted($result));
}

# copy_sign(1, 0) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::copy_sign(1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# copy_sign(1, 1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::copy_sign(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!tainted($result));
}

# copy_sign(12, 9) = 12
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::copy_sign(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!tainted($result));
}

# copy_sign(-12, 9) = 12
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::copy_sign(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!tainted($result));
}

# copy_sign(12, -9) = -12
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::copy_sign(12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(!tainted($result));
}

# copy_sign(-12, -9) = -12
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::copy_sign(-12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(!tainted($result));
}

# copy_sign(581, 3) = 581
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::copy_sign(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!tainted($result));
}

# copy_sign(581, -3) = -581
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::copy_sign(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(!tainted($result));
}

# copy_sign(-581, 3) = 581
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::copy_sign(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg1->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $arg2->taint(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $arg1->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $arg2->taint(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!tainted($result));
}

# copy_sign(-581, -3) = -581
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::copy_sign($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::copy_sign(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg1->copy_sign(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok($result->sensitive);

    $arg2->sensitive(1);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok($result->sensitive);

    $arg1->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok($result->sensitive);

    $arg2->sensitive(0);
    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(!$result->sensitive);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::copy_sign($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::copy_sign($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -581);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}


"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
