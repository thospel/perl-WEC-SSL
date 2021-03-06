#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 011_subtract.t'
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

my @methods = qw(subtract);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# subtract(-1, -1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::subtract(-1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = -1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -1);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(-1, 0) = -1
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::subtract(-1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = -1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -1);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(-1, 1) = -2
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::subtract(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = -1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -2);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -2);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -1);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(0, -1) = 1
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::subtract(0, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 0 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 0);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(0, 0) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::subtract(0, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 0 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 0);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(0, 1) = -1
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::subtract(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 0 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 0);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(1, -1) = 2
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::subtract(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 2);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 2);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 1);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(1, 0) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::subtract(1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 1);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(1, 1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::subtract(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 1);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(12, 9) = 3
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::subtract(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 12 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 3);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 12);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 3);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 12);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(-12, 9) = -21
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::subtract(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = -12 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -21);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -12);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -21);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -12);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -21);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -21);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(12, -9) = 21
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::subtract(12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 12 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 21);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 21);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 12);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 21);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 12);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 21);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 21);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(-12, -9) = -3
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::subtract(-12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = -12 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -3);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -12);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -3);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -12);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(581, 3) = 578
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::subtract(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 581 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 578);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 581);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 578);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 581);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 578);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 578);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(581, -3) = 584
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::subtract(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = 581 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 584);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 581);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 584);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", 581);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 584);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 584);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(-581, 3) = -584
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::subtract(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = -581 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -584);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -584);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -581);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -584);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -581);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -584);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -584);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# subtract(-581, -3) = -578
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::subtract($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::subtract($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::subtract($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::subtract(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->subtract(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1 - -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = -581 - $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -578);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1;
$tmp -= -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -578);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -581);

$tmp = $arg1;
$tmp -= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -578);
ok(!$tmp->sensitive) if feature_sensitive();
ok(!tainted($tmp));
is("$arg1", -581);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -578);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::subtract($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -578);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $tmp -= $arg2;
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
