#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 062_abs_bit.t'
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

my @methods = qw(abs_bit);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# abs_bit(-1, -1) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(-1, -1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_bit(-1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# abs_bit(-1, 0) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(-1, 0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

$result = $arg1->abs_bit(0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "", "Result is not a BigInt");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}


# abs_bit(-1, 1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(-1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}
# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(0, -1) fails
$arg1 = Big->new(0);
$arg2 = Big->new(-1);
ok(!tainted($arg1));
ok(!tainted($arg2));

$result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { WEC::SSL::BigInt::abs_bit(0, -1) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { $arg1->abs_bit($arg2) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { $arg1->abs_bit(-1) };
like($@, qr/\QBitnumber too negative/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
    like($@, qr/\QBitnumber too negative/i);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
    like($@, qr/\QBitnumber too negative/i);
}

# abs_bit(0, 0) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(0);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(0, 0);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(0);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(0, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(1, -1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(1, -1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

$result = $arg1->abs_bit(-1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}


# abs_bit(1, 0) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(0);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(1, 0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_bit(0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result) ^ !$_);
}

# abs_bit(1, 1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(1);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(12, 9) = 0
$arg1 = Big->new(12);
$arg2 = Big->new(9);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(12, 9);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_bit(9);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(-12, 9) = 0
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(-12, 9);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_bit(9);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}


# abs_bit(12, -9) fails
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { WEC::SSL::BigInt::abs_bit(12, -9) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { $arg1->abs_bit($arg2) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { $arg1->abs_bit(-9) };
like($@, qr/\QBitnumber too negative/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
    like($@, qr/\QBitnumber too negative/i);
}

# Check taint propagation
$arg1->taint(1);
$result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
like($@, qr/\QBitnumber too negative/i);

$arg2->taint(1);
$result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
like($@, qr/\QBitnumber too negative/i);

$arg1->taint(0);
$result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
like($@, qr/\QBitnumber too negative/i);

$arg2->taint(0);
$result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
like($@, qr/\QBitnumber too negative/i);


# abs_bit(-12, 9) = 0
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(-12, 9);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(9);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(581, 3) = 0
$arg1 = Big->new(581);
$arg2 = Big->new(3);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(581, 3);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(3);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(581, -3) = 0
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(581, -3);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(-3);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $arg1->sensitive(1);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(-581, 3) = 0
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(-581, 3);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(3);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(-581, -3) = 0
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

ok(!tainted($arg1));
ok(!tainted($arg2));
$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit(-581, -3);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

$result = $arg1->abs_bit(-3);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

### Setting ####

$result = WEC::SSL::BigInt::abs_bit($tmp=1, 7, 0);
is("$tmp", 1);
isa_ok($tmp, "WEC::SSL::BigInt");
is($result, 0);
ok(!tainted($tmp));
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp=1, 7, 1);
is("$tmp", 129);
isa_ok($tmp, "WEC::SSL::BigInt");
is($result, 0);
ok(!tainted($tmp));
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp=-1, 0, 1);
is("$tmp", -1);
isa_ok($tmp, "WEC::SSL::BigInt");
is($result, 1);
ok(!tainted($tmp));
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp=-1, 7, 0);
is("$tmp", -1);
isa_ok($tmp, "WEC::SSL::BigInt");
is($result, 0);
ok(!tainted($tmp));
ok(!tainted($result));

# abs_bit(-1, -1) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 0);
is(ref($result), "");
ok(!$arg1->sensitive) if feature_sensitive();
is("$arg1", 0);
is($result, 1);

$result = WEC::SSL::BigInt::abs_bit($tmp = -1, -1, 0);
is("$tmp", 0);
isa_ok($tmp, "WEC::SSL::BigInt");
is($result, 1);
ok(!tainted($tmp));
ok(!tainted($result));

$result = eval { $arg1->abs_bit($arg2, 1) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { $arg1->abs_bit(-1, 1) };
like($@, qr/\QBitnumber too negative/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1 = Big->new(-1);
    $arg2 = Big->new(-1);
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 0);
    is(ref($result), "");
    ok($arg1->sensitive ^ !$_);
    is("$arg1", 0);
    is($result, 1);
}

for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2, 0) };
    like($@, qr/\QBitnumber too negative/i);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1) };
    like($@, qr/\QBitnumber too negative/i);
}

is("$arg1", 0);
is("$arg2", -1);

# abs_bit(-1, 0) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
is($result, 1);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", 0);
ok(!tainted($result));
ok(!tainted($arg1));

$result = $arg1->abs_bit(0, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", -1);

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1 = Big->new(-1);
    $arg2 = Big->new(0);
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 0);
    is(ref($result), "");
    is($result, 1);
    is("$arg1", 0);
    ok(tainted($result) ^ !$_);
    ok(tainted($arg1) ^ !$_);
    ok(tainted($arg2) ^ !($_ & 2));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1 = Big->new(-1);
    $arg2 = Big->new(0);
    # Next dummy line somehow causes the argument not to be tainted
    # ANY statement here seems to work
    my $dummy;
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
    is(ref($result), "");
    is($result, 1);
    is("$arg1", -1);
    ok(tainted($result) ^ !$_);
    ok(tainted($arg1) ^ !$_);
    ok(tainted($arg2) ^ !($_ & 2));
}

# abs_bit(-1, 1) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 0);
is(ref($result), "");
is($result, 0);
is("$arg1", -1);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", -3);
ok(!tainted($result));

$result = $arg1->abs_bit(1, 1);
is(ref($result), "");
is($result, 1);
is("$arg1", -3);
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1 = Big->new(-3);
    $arg2 = Big->new(1);
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
    is(ref($result), "");
    ok($arg1->sensitive ^ !$_);
    is("$arg1", -3);
    is($result, 1);
}

for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1 = Big->new(-1);
    $arg2 = Big->new(1);
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 0);
    ok($arg1->sensitive ^ !$_);
    is("$arg1", -1);
    is(ref($result), "");
    is($result, 0);
}

my $arg3;

for (0..(feature_sensitive() ? 7 : -1)) {
    $arg1 = Big->new(-1);
    $arg2 = Big->new(1);
    $arg3 = Big->new(3);
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $arg3->sensitive($_ & 4);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, $arg3);
    ok($arg1->sensitive ^ !$_);
    is("$arg1", -3);
    is(ref($result), "");
    is($result, 0);
    ok($arg2->sensitive ^ !($_ & 2));
}

for (0..(feature_sensitive() ? 7 : -1)) {
    $arg1 = Big->new(-3);
    $arg2 = Big->new(1);
    $arg3 = Big->new(0);
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $arg3->sensitive($_ & 4);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, $arg3);
    ok($arg1->sensitive ^ !$_);
    is("$arg1", -1);
    is(ref($result), "");
    is($result, 1);
    ok($arg2->sensitive ^ !($_ & 2));
}

# Check taint propagation
$arg1 = Big->new(-1);
$arg2 = Big->new(1);
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = WEC::SSL::BigInt::abs_bit($arg1, $arg2);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result) ^ !$_);
}

# abs_bit(0, -1) fails
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { WEC::SSL::BigInt::abs_bit(0, -1, 1) };
like($@, qr/\QModification of a read-only value attempted at /i);

$result = eval { $arg1->abs_bit($arg2, 0) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { $arg1->abs_bit(-1, 0) };
like($@, qr/\QBitnumber too negative/i);

# abs_bit(0, 0) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", 1);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp = 0, 0, 1);
is(ref($result), "");
is($result, 0);
is("$tmp", 1);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", 0);
ok(!tainted($result));

$result = $arg1->abs_bit(0, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", 1);
ok(!tainted($result));

# abs_bit(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", 2);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp = 0, 1, 0);
is(ref($result), "");
is($result, 0);
is("$tmp", 0);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 1);
is(ref($result), "");
is($result, 1);
is("$arg1", 2);
ok(!tainted($result));

$result = $arg1->abs_bit(1, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", 0);
ok(!tainted($result));

# abs_bit(1, -1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
is(ref($result), "");
is($result, 1);
is("$arg1", 1);
isa_ok($arg1, "Big");
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", 0);
ok(!tainted($result));

$result = eval { $arg1->abs_bit(-1, 0) };
like($@, qr/^Bitnumber too negative at /i);

# abs_bit(12, 9) = 0
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", 524);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp = 12, 9, 1);
is(ref($result), "");
is($result, 0);
is("$tmp", 524);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 1);
is(ref($result), "");
is($result, 1);
is("$arg1", 524);
ok(!tainted($result));

$result = $arg1->abs_bit(9, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", 12);
ok(!tainted($result));

# abs_bit(-12, 9) = 1
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", -524);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp=-12, 9, 0);
is(ref($result), "");
is($result, 0);
is("$tmp", -12);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", -12);
ok(!tainted($result));

$result = $arg1->abs_bit(9, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", -524);
ok(!tainted($result));

# abs_bit(12, -9) fails
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = eval { WEC::SSL::BigInt::abs_bit($arg1, $arg2) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { WEC::SSL::BigInt::abs_bit(12, -9) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { $arg1->abs_bit($arg2) };
like($@, qr/\QBitnumber too negative/i);

$result = eval { $arg1->abs_bit(-9) };
like($@, qr/\QBitnumber too negative/i);

# abs_bit(581, 3) = 0
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", 589);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp = 581, 3, 0);
is(ref($result), "");
is($result, 0);
is("$tmp", 581);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", 581);
ok(!tainted($result));

$result = $arg1->abs_bit(3, 0);
is(ref($result), "");
is($result, 0);
is("$arg1", 581);
ok(!tainted($result));

# abs_bit(581, -3) = 0
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", 709);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp=581, -3, 1);
is(ref($result), "");
is($result, 0);
is("$tmp", 709);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 1);
is(ref($result), "");
is($result, 1);
is("$arg1", 709);
ok(!tainted($result));

$result = $arg1->abs_bit(-3, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", 581);
ok(!tainted($result));

# abs_bit(-581, 3) = 1
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 0);
is(ref($result), "");
is($result, 0);
is("$arg1", -581);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp=-581, 3, 0);
is(ref($result), "");
is($result, 0);
is("$arg1", -581);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", -589);
ok(!tainted($result));

$result = $arg1->abs_bit(3, 1);
is(ref($result), "");
is($result, 1);
is("$arg1", -589);
ok(!tainted($result));

# abs_bit(-581, -3) = 1
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::abs_bit($arg1, $arg2, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", -709);
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs_bit($tmp=-581, -3, 0);
is(ref($result), "");
is($result, 0);
is("$tmp", -581);
ok(!tainted($result));

$result = $arg1->abs_bit($arg2, 0);
is(ref($result), "");
is($result, 1);
is("$arg1", -581);
ok(!tainted($result));
$result = $arg1->abs_bit(-3, 1);
is(ref($result), "");
is($result, 0);
is("$arg1", -709);
ok(!tainted($result));
#####

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
