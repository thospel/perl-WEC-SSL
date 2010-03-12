#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 013_perl_divide.t'
use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::BigInt
;

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
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::perl_divide(-1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

# perl_divide(-1, -1) = (1, 0)
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

($q, $r) = WEC::SSL::BigInt::perl_divide(-1, -1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!tainted($q));
ok(!tainted($r));


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
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);
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
$arg1->sensitive(1);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);
}


# perl_divide(-1, 1) = -1
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::perl_divide(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!tainted($result));

# perl_divide(-1, 1) = (-1, 0)
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

($q, $r) = WEC::SSL::BigInt::perl_divide(-1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(0, -1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::perl_divide(0, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

# perl_divide(0, -1) = (0, 0)
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

($q, $r) = WEC::SSL::BigInt::perl_divide(0, -1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!tainted($q));
ok(!tainted($r));


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
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);
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
$arg1->sensitive(1);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);
}


# perl_divide(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::perl_divide(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

# perl_divide(0, 1) = (0, 0)
$arg1 = Big->new(0);
$arg2 = Big->new(1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

($q, $r) = WEC::SSL::BigInt::perl_divide(0, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 0);
is("$r", 0);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(1, -1) = -1
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::perl_divide(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!tainted($result));

# perl_divide(1, -1) = (-1, 0)
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

($q, $r) = WEC::SSL::BigInt::perl_divide(1, -1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 0);
ok(!tainted($q));
ok(!tainted($r));


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
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    $result = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);
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
$arg1->sensitive(1);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
for (0..(feature_taint() ? 3 : -1)) {
    $arg1->taint($_ & 1);
    $arg2->taint($_ & 2);
    ($q, $r) = eval { WEC::SSL::BigInt::perl_divide($arg1, $arg2) };
    like($@, qr/\Qdiv by zero/i);
}


# perl_divide(1, 1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::perl_divide(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

# perl_divide(1, 1) = (1, 0)
$arg1 = Big->new(1);
$arg2 = Big->new(1);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

($q, $r) = WEC::SSL::BigInt::perl_divide(1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 0);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(12, 9) = 1
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::perl_divide(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

# perl_divide(12, 9) = (1, 3)
$arg1 = Big->new(12);
$arg2 = Big->new(9);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

($q, $r) = WEC::SSL::BigInt::perl_divide(12, 9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", 3);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(-12, 9) = -1
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::perl_divide(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!tainted($result));

# perl_divide(-12, 9) = (-1, -3)
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

($q, $r) = WEC::SSL::BigInt::perl_divide(-12, 9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", -3);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(12, -9) = -1
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::perl_divide(12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!tainted($result));

# perl_divide(12, -9) = (-1, 3)
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

($q, $r) = WEC::SSL::BigInt::perl_divide(12, -9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -1);
is("$r", 3);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(-12, -9) = 1
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::perl_divide(-12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

# perl_divide(-12, -9) = (1, -3)
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

($q, $r) = WEC::SSL::BigInt::perl_divide(-12, -9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-9);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 1);
is("$r", -3);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(581, 3) = 193
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::perl_divide(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!tainted($result));

# perl_divide(581, 3) = (193, 2)
$arg1 = Big->new(581);
$arg2 = Big->new(3);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

($q, $r) = WEC::SSL::BigInt::perl_divide(581, 3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", 2);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(581, -3) = -193
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::perl_divide(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!tainted($result));

# perl_divide(581, -3) = (-193, 2)
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

($q, $r) = WEC::SSL::BigInt::perl_divide(581, -3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", 2);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(-581, 3) = -193
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::perl_divide(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -193);
ok(!tainted($result));

# perl_divide(-581, 3) = (-193, -2)
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

($q, $r) = WEC::SSL::BigInt::perl_divide(-581, 3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", -193);
is("$r", -2);
ok(!tainted($q));
ok(!tainted($r));


# perl_divide(-581, -3) = 193
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::perl_divide(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->perl_divide(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 193);
ok(!tainted($result));

# perl_divide(-581, -3) = (193, -2)
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = WEC::SSL::BigInt::perl_divide($arg2, $arg1, 1);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
$tmp = $arg1->copy;
($q, $r) = WEC::SSL::BigInt::perl_divide($tmp, $arg2, undef);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

($q, $r) = WEC::SSL::BigInt::perl_divide(-581, -3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide($arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
($q, $r) = $arg1->perl_divide(-3);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive);
ok(!tainted($q));
ok(!tainted($r));
# Check sensitive propagation
$arg1->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok($q->sensitive);

$arg2->sensitive(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok($q->sensitive);

$arg1->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok($q->sensitive);

$arg2->sensitive(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!$q->sensitive);

# Check taint propagation
$arg1->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(1);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(tainted($q));
ok(tainted($r));

$arg1->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(tainted($q));
ok(tainted($r));

$arg2->taint(0);
($q, $r) = WEC::SSL::BigInt::perl_divide($arg1, $arg2);
isa_ok($q, "WEC::SSL::BigInt");
is(ref($r), "");
is("$q", 193);
is("$r", -2);
ok(!tainted($q));
ok(!tainted($r));

















"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
