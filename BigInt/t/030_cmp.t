#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 030_cmp.t'
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

my @methods = qw(cmp);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# cmp(-1, -1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", -1);

$result = WEC::SSL::BigInt::cmp(-1, -1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->cmp(-1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1 <=> -1;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = -1 <=> $arg2;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# cmp(-1, 0) = -1
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", -1);

$result = WEC::SSL::BigInt::cmp(-1, 0);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp(0);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> 0;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = -1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result) ^ !$_);
}

# cmp(-1, 1) = -1
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", -1);

$result = WEC::SSL::BigInt::cmp(-1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp(1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> 1;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = -1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result) ^ !$_);
}

# cmp(0, -1) = 1
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 0);

$result = WEC::SSL::BigInt::cmp(0, -1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp(-1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> -1;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = 0 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# cmp(0, 0) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 0);

$result = WEC::SSL::BigInt::cmp(0, 0);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->cmp(0);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1 <=> 0;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = 0 <=> $arg2;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# cmp(0, 1) = -1
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", 0);

$result = WEC::SSL::BigInt::cmp(0, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp(1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> 1;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = 0 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result) ^ !$_);
}

# cmp(1, -1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 1);

$result = WEC::SSL::BigInt::cmp(1, -1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp(-1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> -1;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = 1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# cmp(1, 0) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 1);

$result = WEC::SSL::BigInt::cmp(1, 0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp(0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> 0;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = 1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# cmp(1, 1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 1);

$result = WEC::SSL::BigInt::cmp(1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->cmp(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1 <=> 1;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = 1 <=> $arg2;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# cmp(12, 9) = 1
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 12);

$result = WEC::SSL::BigInt::cmp(12, 9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp(9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> 9;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = 12 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# cmp(-12, 9) = -1
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", -12);

$result = WEC::SSL::BigInt::cmp(-12, 9);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp(9);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> 9;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = -12 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result) ^ !$_);
}

# cmp(12, -9) = 1
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 12);

$result = WEC::SSL::BigInt::cmp(12, -9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp(-9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> -9;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = 12 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# cmp(-12, -9) = -1
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", -12);

$result = WEC::SSL::BigInt::cmp(-12, -9);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp(-9);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> -9;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = -12 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result) ^ !$_);
}

# cmp(581, 3) = 1
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 581);

$result = WEC::SSL::BigInt::cmp(581, 3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp(3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> 3;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = 581 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# cmp(581, -3) = 1
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 581);

$result = WEC::SSL::BigInt::cmp(581, -3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->cmp(-3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1 <=> -3;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = 581 <=> $arg2;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# cmp(-581, 3) = -1
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", -581);

$result = WEC::SSL::BigInt::cmp(-581, 3);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp(3);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> 3;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = -581 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result) ^ !$_);
}

# cmp(-581, -3) = -1
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", -581);

$result = WEC::SSL::BigInt::cmp(-581, -3);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->cmp(-3);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1 <=> -3;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = -581 <=> $arg2;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result) ^ !$_);
}

for (0..(feature_taint() ? 3 : -1)) {
    $arg1 = Big->new(-581);
    $arg2 = Big->new(-3);

    # Next dummy line somehow causes the argument not to be tainted
    # ANY statement here seems to work
    my $dummy;

    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::cmp($arg1, $arg2, undef);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result) ^ !$_);

    is(ref($arg1), "");
    is($arg1, -1);
    ok(tainted($arg1) ^ !$_);
}


"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
