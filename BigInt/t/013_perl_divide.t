#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 013_perl_divide.t'
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

my @methods = qw(perl_divide);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result, $q, $r);

# perl_divide(-1, -1) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::perl_divide(-1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
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

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-1, -1) = (1, 0)
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

($q, $r) = WEC::SSL::BigInt::perl_divide(-1, -1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 1);
    is("$r", 0);
    ok($q->sensitive ^!$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    is("$q", 1);
    ok($q->sensitive ^ !$_);
    is("$tmp", 1);
    ok($tmp->sensitive ^!$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 1);
    is("$r", 0);
    ok($q->taint ^!$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", 1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", 1);
    ok(tainted($tmp) ^!$_);
    ok($tmp->taint ^!$_);
}

# perl_divide(-1, 0) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", -1);

$result = eval { WEC::SSL::BigInt::perl_divide(-1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_divide($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_divide(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# perl_divide(-1, 0) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", -1);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide(-1, 0) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { $arg1->perl_divide($arg2) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { $arg1->perl_divide(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# perl_divide(-1, 1) = -1
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::perl_divide(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}
# perl_divide(-1, 1) = (-1, 0)
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

($q, $r) = WEC::SSL::BigInt::perl_divide(-1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", -1);
    is("$r", 0);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    is("$q", -1);
    ok($q->sensitive ^ !$_);
    is("$tmp", -1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", -1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", -1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", -1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(0, -1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::perl_divide(0, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
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

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(0, -1) = (0, 0)
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

($q, $r) = WEC::SSL::BigInt::perl_divide(0, -1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 0);
    is("$r", 0);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    is("$q", 0);
    ok($q->sensitive ^ !$_);
    is("$tmp", 0);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", 0);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", 0);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(0, 0) fails
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 0);

$result = eval { WEC::SSL::BigInt::perl_divide(0, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_divide($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_divide(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# perl_divide(0, 0) fails
$arg1 = Big->new(0);
$arg2 = Big->new(0);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 0);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide(0, 0) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { $arg1->perl_divide($arg2) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { $arg1->perl_divide(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# perl_divide(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::perl_divide(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
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

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(0, 1) = (0, 0)
$arg1 = Big->new(0);
$arg2 = Big->new(1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

($q, $r) = WEC::SSL::BigInt::perl_divide(0, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 0);
    is("$r", 0);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    is("$q", 0);
    ok($q->sensitive ^ !$_);
    is("$tmp", 0);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", 0);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", 0);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", 0);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(1, -1) = -1
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::perl_divide(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(1, -1) = (-1, 0)
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

($q, $r) = WEC::SSL::BigInt::perl_divide(1, -1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", -1);
    is("$r", 0);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    is("$q", -1);
    ok($q->sensitive ^ !$_);
    is("$tmp", -1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", -1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", -1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", -1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(1, 0) fails
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 1);

$result = eval { WEC::SSL::BigInt::perl_divide(1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_divide($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_divide(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    $result = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# perl_divide(1, 0) fails
$arg1 = Big->new(1);
$arg2 = Big->new(0);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 1);

($q, $r) = eval { WEC::SSL::BigInt::perl_divide(1, 0) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { $arg1->perl_divide($arg2) };
like($@, qr/\Qdiv by zero/i);

($q, $r) = eval { $arg1->perl_divide(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok($tmp->sensitive ^ !($_ & 1));
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);

    $tmp = $arg1->copy;
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef) };
    like($@, qr/\Qdiv by zero/i);
    ok(tainted($tmp) ^ !($_ & 1));
    ok($tmp->taint ^ !($_ & 1));
}

# perl_divide(1, 1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::perl_divide(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
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

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(1, 1) = (1, 0)
$arg1 = Big->new(1);
$arg2 = Big->new(1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

($q, $r) = WEC::SSL::BigInt::perl_divide(1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 1);
    is("$r", 0);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    is("$q", 1);
    ok($q->sensitive ^ !$_);
    is("$tmp", 1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", 1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 0);
    ok(tainted($r) ^ !$_);
    is("$q", 1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(12, 9) = 1
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::perl_divide(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
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

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(12, 9) = (1, 3)
$arg1 = Big->new(12);
$arg2 = Big->new(9);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

($q, $r) = WEC::SSL::BigInt::perl_divide(12, 9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 1);
    is("$r", 3);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 3);
    is("$q", 1);
    ok($q->sensitive ^ !$_);
    is("$tmp", 1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 3);
    ok(tainted($r) ^ !$_);
    is("$q", 1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 3);
    ok(tainted($r) ^ !$_);
    is("$q", 1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-12, 9) = -1
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::perl_divide(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-12, 9) = (-1, -3)
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

($q, $r) = WEC::SSL::BigInt::perl_divide(-12, 9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", -1);
    is("$r", -3);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -3);
    is("$q", -1);
    ok($q->sensitive ^ !$_);
    is("$tmp", -1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -3);
    ok(tainted($r) ^ !$_);
    is("$q", -1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -3);
    ok(tainted($r) ^ !$_);
    is("$q", -1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", -1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(12, -9) = -1
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::perl_divide(12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(12, -9) = (-1, 3)
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

($q, $r) = WEC::SSL::BigInt::perl_divide(12, -9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", -1);
    is("$r", 3);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 3);
    is("$q", -1);
    ok($q->sensitive ^ !$_);
    is("$tmp", -1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 3);
    ok(tainted($r) ^ !$_);
    is("$q", -1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 3);
    ok(tainted($r) ^ !$_);
    is("$q", -1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", -1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-12, -9) = 1
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::perl_divide(-12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
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

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-12, -9) = (1, -3)
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

($q, $r) = WEC::SSL::BigInt::perl_divide(-12, -9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 1);
    is("$r", -3);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -3);
    is("$q", 1);
    ok($q->sensitive ^ !$_);
    is("$tmp", 1);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -3);
    ok(tainted($r) ^ !$_);
    is("$q", 1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -3);
    ok(tainted($r) ^ !$_);
    is("$q", 1);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", 1);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(581, 3) = 193
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::perl_divide(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 193);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 193);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 193);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 193);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 193);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 193);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(581, 3) = (193, 2)
$arg1 = Big->new(581);
$arg2 = Big->new(3);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

($q, $r) = WEC::SSL::BigInt::perl_divide(581, 3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 193);
    is("$r", 2);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 2);
    is("$q", 193);
    ok($q->sensitive ^ !$_);
    is("$tmp", 193);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 2);
    ok(tainted($r) ^ !$_);
    is("$q", 193);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 2);
    ok(tainted($r) ^ !$_);
    is("$q", 193);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", 193);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(581, -3) = -193
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::perl_divide(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -193);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -193);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -193);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -193);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -193);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -193);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(581, -3) = (-193, 2)
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

($q, $r) = WEC::SSL::BigInt::perl_divide(581, -3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", -193);
    is("$r", 2);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 2);
    is("$q", -193);
    ok($q->sensitive ^ !$_);
    is("$tmp", -193);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 2);
    ok(tainted($r) ^ !$_);
    is("$q", -193);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", 2);
    ok(tainted($r) ^ !$_);
    is("$q", -193);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", -193);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-581, 3) = -193
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::perl_divide(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -193);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -193);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -193);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -193);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -193);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", -193);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-581, 3) = (-193, -2)
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

($q, $r) = WEC::SSL::BigInt::perl_divide(-581, 3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", -193);
    is("$r", -2);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -2);
    is("$q", -193);
    ok($q->sensitive ^ !$_);
    is("$tmp", -193);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -2);
    ok(tainted($r) ^ !$_);
    is("$q", -193);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -2);
    ok(tainted($r) ^ !$_);
    is("$q", -193);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", -193);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-581, -3) = 193
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::perl_divide(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg1->perl_divide(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 193);
    ok($result->sensitive ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 193);
    ok($result->sensitive ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 193);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    $result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 193);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);

    $tmp = $arg1->copy;
    $result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 193);
    ok(tainted($result) ^ !$_);
    ok($result->taint ^ !$_);
    isa_ok($tmp, "WEC::SSL::BigInt");
    is("$tmp", 193);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

# perl_divide(-581, -3) = (193, -2)
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

($q, $r) = WEC::SSL::BigInt::perl_divide(-581, -3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive) if feature_sensitive();
ok(!tainted($q));
ok(!tainted($r));

# Check sensitive propagation
for (0..(feature_sensitive() ? 3 : -1)) {
    $arg1->sensitive($_ & 1);
    $arg2->sensitive($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$q", 193);
    is("$r", -2);
    ok($q->sensitive ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -2);
    is("$q", 193);
    ok($q->sensitive ^ !$_);
    is("$tmp", 193);
    ok($tmp->sensitive ^ !$_);
}

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);

    ($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -2);
    ok(tainted($r) ^ !$_);
    is("$q", 193);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);

    $tmp = $arg1->copy;
    ($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
    isa_ok($q, "WEC::SSL::BigInt");
    is(ref($r), "");
    is("$r", -2);
    ok(tainted($r) ^ !$_);
    is("$q", 193);
    ok(tainted($q) ^ !$_);
    ok($q->taint ^ !$_);
    is("$tmp", 193);
    ok(tainted($tmp) ^ !$_);
    ok($tmp->taint ^ !$_);
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
