#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 014_remainder.t'
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

my @methods = qw(remainder);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# remainder(-1, -1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::remainder(-1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));


# remainder(-1, 0) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", -1);

$result = eval { WEC::SSL::BigInt::remainder(-1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
$arg1->taint(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->taint(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->taint(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->taint(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);


# remainder(-1, 1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::remainder(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));


# remainder(0, -1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::remainder(0, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));


# remainder(0, 0) fails
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 0);

$result = eval { WEC::SSL::BigInt::remainder(0, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
$arg1->taint(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->taint(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->taint(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->taint(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);


# remainder(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::remainder(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));


# remainder(1, -1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::remainder(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));


# remainder(1, 0) fails
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 1);

$result = eval { WEC::SSL::BigInt::remainder(1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
$arg1->taint(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->taint(1);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->taint(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->taint(0);
$result = eval { WEC::SSL::BigInt::remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);


# remainder(1, 1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::remainder(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));


# remainder(12, 9) = 3
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::remainder(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!tainted($result));


# remainder(-12, 9) = -3
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::remainder(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!tainted($result));


# remainder(12, -9) = 3
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::remainder(12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!tainted($result));


# remainder(-12, -9) = -3
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::remainder(-12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!tainted($result));


# remainder(581, 3) = 2
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::remainder(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!tainted($result));


# remainder(581, -3) = 2
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::remainder(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!tainted($result));


# remainder(-581, 3) = -2
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::remainder(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!tainted($result));


# remainder(-581, -3) = -2
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::remainder($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::remainder($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::remainder(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->remainder(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::remainder($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!tainted($result));

















"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
