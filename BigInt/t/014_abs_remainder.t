#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 014_abs_remainder.t'
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

my @methods = qw(abs_remainder);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# abs_remainder(-1, -1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::abs_remainder(-1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}


# abs_remainder(-1, 0) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", -1);

$result = eval { WEC::SSL::BigInt::abs_remainder(-1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->abs_remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->abs_remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# abs_remainder(-1, 1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::abs_remainder(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(0, -1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::abs_remainder(0, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(0, 0) fails
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 0);

$result = eval { WEC::SSL::BigInt::abs_remainder(0, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->abs_remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->abs_remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# abs_remainder(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::abs_remainder(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(1, -1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::abs_remainder(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(1, 0) fails
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 1);

$result = eval { WEC::SSL::BigInt::abs_remainder(1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->abs_remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->abs_remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = eval { WEC::SSL::BigInt::abs_remainder($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# abs_remainder(1, 1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::abs_remainder(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(12, 9) = 3
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::abs_remainder(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 3);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 3);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(-12, 9) = 6
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::abs_remainder(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 6);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 6);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(12, -9) = 3
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::abs_remainder(12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 3);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 3);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(-12, -9) = 6
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::abs_remainder(-12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 6);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 6);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(581, 3) = 2
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::abs_remainder(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);
    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive ^ !$_);
}

# abs_remainder(581, -3) = 2
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::abs_remainder(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 2);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 2);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(-581, 3) = 1
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::abs_remainder(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# abs_remainder(-581, -3) = 1
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::abs_remainder(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->abs_remainder(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::abs_remainder($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::abs_remainder($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
