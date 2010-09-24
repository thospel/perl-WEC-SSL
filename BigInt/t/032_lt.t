#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 032_lt.t'
#########################
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

my @methods = qw(lt);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# lt(-1, -1) = ""
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", -1);

$result = WEC::SSL::BigInt::lt(-1, -1);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(-1);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < -1;
is(ref($result), "");
is($result, "");
$result = -1 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}


# lt(-1, 0) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
is("$arg1", -1);

$result = WEC::SSL::BigInt::lt(-1, 0);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt(0);
is(ref($result), "");
is($result, 1);
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, 1);
$result = $arg1 < 0;
is(ref($result), "");
is($result, 1);
$result = -1 < $arg2;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
is("$arg1", -1);

$result = WEC::SSL::BigInt::lt(-1, 1);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt(1);
is(ref($result), "");
is($result, 1);
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, 1);
$result = $arg1 < 1;
is(ref($result), "");
is($result, 1);
$result = -1 < $arg2;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 0);

$result = WEC::SSL::BigInt::lt(0, -1);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(-1);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < -1;
is(ref($result), "");
is($result, "");
$result = 0 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 0);

$result = WEC::SSL::BigInt::lt(0, 0);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(0);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < 0;
is(ref($result), "");
is($result, "");
$result = 0 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
is("$arg1", 0);

$result = WEC::SSL::BigInt::lt(0, 1);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt(1);
is(ref($result), "");
is($result, 1);
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, 1);
$result = $arg1 < 1;
is(ref($result), "");
is($result, 1);
$result = 0 < $arg2;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 1);

$result = WEC::SSL::BigInt::lt(1, -1);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(-1);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < -1;
is(ref($result), "");
is($result, "");
$result = 1 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 1);

$result = WEC::SSL::BigInt::lt(1, 0);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(0);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < 0;
is(ref($result), "");
is($result, "");
$result = 1 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 1);

$result = WEC::SSL::BigInt::lt(1, 1);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(1);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < 1;
is(ref($result), "");
is($result, "");
$result = 1 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 12);

$result = WEC::SSL::BigInt::lt(12, 9);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(9);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < 9;
is(ref($result), "");
is($result, "");
$result = 12 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
is("$arg1", -12);

$result = WEC::SSL::BigInt::lt(-12, 9);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt(9);
is(ref($result), "");
is($result, 1);
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, 1);
$result = $arg1 < 9;
is(ref($result), "");
is($result, 1);
$result = -12 < $arg2;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 12);

$result = WEC::SSL::BigInt::lt(12, -9);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(-9);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < -9;
is(ref($result), "");
is($result, "");
$result = 12 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
is("$arg1", -12);

$result = WEC::SSL::BigInt::lt(-12, -9);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt(-9);
is(ref($result), "");
is($result, 1);
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, 1);
$result = $arg1 < -9;
is(ref($result), "");
is($result, 1);
$result = -12 < $arg2;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 581);

$result = WEC::SSL::BigInt::lt(581, 3);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(3);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < 3;
is(ref($result), "");
is($result, "");
$result = 581 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, "");
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, "");
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, "");
is("$arg1", 581);

$result = WEC::SSL::BigInt::lt(581, -3);
is(ref($result), "");
is($result, "");
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, "");
$result = $arg1->lt(-3);
is(ref($result), "");
is($result, "");
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, "");
$result = $arg1 < -3;
is(ref($result), "");
is($result, "");
$result = 581 < $arg2;
is(ref($result), "");
is($result, "");

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, "");
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
is("$arg1", -581);

$result = WEC::SSL::BigInt::lt(-581, 3);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt(3);
is(ref($result), "");
is($result, 1);
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, 1);
$result = $arg1 < 3;
is(ref($result), "");
is($result, 1);
$result = -581 < $arg2;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::lt($arg1, $arg2);
is(ref($result), "");
is($result, 1);
$result = WEC::SSL::BigInt::lt($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::lt($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
is("$arg1", -581);

$result = WEC::SSL::BigInt::lt(-581, -3);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt($arg2);
is(ref($result), "");
is($result, 1);
$result = $arg1->lt(-3);
is(ref($result), "");
is($result, 1);
$result = $arg1 < $arg2;
is(ref($result), "");
is($result, 1);
$result = $arg1 < -3;
is(ref($result), "");
is($result, 1);
$result = -581 < $arg2;
is(ref($result), "");
is($result, 1);

# Check operation under sensitivity
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check operation under taint
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::lt($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}


"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
