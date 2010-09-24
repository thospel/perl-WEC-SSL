#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 063_mask_bits.t'
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

my @methods = qw(mask_bits);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# mask_bits(-1, -1) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
like($@, qr/\QBits too negative/i);

$result = eval { WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1) };
like($@, qr/\QBits too negative/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef) };
like($@, qr/\QBits too negative/i);
is("$arg1", -1);

$result = eval { WEC::SSL::BigInt::mask_bits(-1, -1) };
like($@, qr/\QBits too negative/i);

$result = eval { $arg1->mask_bits($arg2) };
like($@, qr/\QBits too negative/i);

$result = eval { $arg1->mask_bits(-1) };
like($@, qr/\QBits too negative/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1 ? 1 : 0);
    $arg2->sensitive($_ & 2 ? 1 : 0);
    $result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
    like($@, qr/\QBits too negative/i);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1 ? 1 : 0);
    $arg2->taint($_ & 2 ? 1 : 0);
    $result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
    like($@, qr/\QBits too negative/i);
}

# mask_bits(-1, 0) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::mask_bits(-1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1 ? 1 : 0);
    $arg2->sensitive($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1 ? 1 : 0);
    $arg2->taint($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
}

# mask_bits(-1, 1) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::mask_bits(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1 ? 1 : 0);
    $arg2->sensitive($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1 ? 1 : 0);
    $arg2->taint($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
}

# mask_bits(0, -1) fails
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
like($@, qr/\QBits too negative/i);

$result = eval { WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1) };
like($@, qr/\QBits too negative/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef) };
like($@, qr/\QBits too negative/i);
is("$arg1", 0);

$result = eval { WEC::SSL::BigInt::mask_bits(0, -1) };
like($@, qr/\QBits too negative/i);

$result = eval { $arg1->mask_bits($arg2) };
like($@, qr/\QBits too negative/i);

$result = eval { $arg1->mask_bits(-1) };
like($@, qr/\QBits too negative/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1 ? 1 : 0);
    $arg2->sensitive($_ & 2 ? 1 : 0);
    $result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
    like($@, qr/\QBits too negative/i);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1 ? 1 : 0);
    $arg2->taint($_ & 2 ? 1 : 0);
    $result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
    like($@, qr/\QBits too negative/i);
}

# mask_bits(0, 0) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::mask_bits(0, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1 ? 1 : 0);
    $arg2->sensitive($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1 ? 1 : 0);
    $arg2->taint($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
}

# mask_bits(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::mask_bits(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1 ? 1 : 0);
    $arg2->sensitive($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1 ? 1 : 0);
    $arg2->taint($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
}

# mask_bits(1, -1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::mask_bits(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1 ? 1 : 0);
    $arg2->sensitive($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1 ? 1 : 0);
    $arg2->taint($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
}

# mask_bits(1, 0) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::mask_bits(1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1 ? 1 : 0);
    $arg2->taint($_ & 2 ? 1 : 0);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
}

# mask_bits(1, 1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::mask_bits(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
}

# mask_bits(12, 9) = 12
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::mask_bits(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result) ^ !$_);
}

# mask_bits(-12, 9) = 500
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 500);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 500);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 500);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::mask_bits(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 500);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 500);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 500);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 500);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 500);
    ok(tainted($result) ^ !$_);
}

# mask_bits(12, -9) fails
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
like($@, qr/\QBits too negative/i);

$result = eval { WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1) };
like($@, qr/\QBits too negative/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef) };
like($@, qr/\QBits too negative/i);
is("$arg1", 12);

$result = eval { WEC::SSL::BigInt::mask_bits(12, -9) };
like($@, qr/\QBits too negative/i);

$result = eval { $arg1->mask_bits($arg2) };
like($@, qr/\QBits too negative/i);

$result = eval { $arg1->mask_bits(-9) };
like($@, qr/\QBits too negative/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
    like($@, qr/\QBits too negative/i);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
    like($@, qr/\QBits too negative/i);
}

# mask_bits(-12, -9) fails
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
like($@, qr/\QBits too negative/i);

$result = eval { WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1) };
like($@, qr/\QBits too negative/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef) };
like($@, qr/\QBits too negative/i);
is("$arg1", -12);

$result = eval { WEC::SSL::BigInt::mask_bits(-12, -9) };
like($@, qr/\QBits too negative/i);

$result = eval { $arg1->mask_bits($arg2) };
like($@, qr/\QBits too negative/i);

$result = eval { $arg1->mask_bits(-9) };
like($@, qr/\QBits too negative/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
    like($@, qr/\QBits too negative/i);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = eval { WEC::SSL::BigInt::mask_bits($arg1, $arg2) };
    like($@, qr/\QBits too negative/i);
}

# mask_bits(581, 3) = 5
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::mask_bits(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 5);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 5);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 5);
    ok(tainted($result) ^ !$_);
}

# mask_bits(581, -3) = 4
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::mask_bits(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok(tainted($result) ^ !$_);
}

# mask_bits(-581, 3) = 3
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::mask_bits(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result) ^ !$_);
}

# mask_bits(-581, -3) = 3
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = WEC::SSL::BigInt::mask_bits($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::mask_bits(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

$result = $arg1->mask_bits(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result)) if feature_taint();

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::mask_bits($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    my $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::mask_bits($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result) ^ !$_, "taint $_");
    ok($result->taint ^ !$_, "taint $_");
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 3);
    ok(tainted($tmp) ^ !$_, "taint $_");
    ok($tmp->taint ^ !$_, "taint $_");
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
