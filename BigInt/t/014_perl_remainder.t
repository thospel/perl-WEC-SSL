#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 014_perl_remainder.t'

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok("WEC::SSL::BigInt") };

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(perl_remainder);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# perl_remainder(-1, -1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", -1);

$result = WEC::SSL::BigInt::perl_remainder(-1, -1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder(-1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# perl_remainder(-1, 0) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", -1);

$result = eval { WEC::SSL::BigInt::perl_remainder(-1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check operation under sensitivity
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);


# perl_remainder(-1, 1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", -1);

$result = WEC::SSL::BigInt::perl_remainder(-1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# perl_remainder(0, -1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 0);

$result = WEC::SSL::BigInt::perl_remainder(0, -1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder(-1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# perl_remainder(0, 0) fails
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 0);

$result = eval { WEC::SSL::BigInt::perl_remainder(0, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check operation under sensitivity
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);


# perl_remainder(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 0);

$result = WEC::SSL::BigInt::perl_remainder(0, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# perl_remainder(1, -1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 1);

$result = WEC::SSL::BigInt::perl_remainder(1, -1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder(-1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# perl_remainder(1, 0) fails
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 1);

$result = eval { WEC::SSL::BigInt::perl_remainder(1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_remainder($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->perl_remainder(0) };
like($@, qr/\Qdiv by zero/i);

# Check operation under sensitivity
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::perl_remainder($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);


# perl_remainder(1, 1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 1);

$result = WEC::SSL::BigInt::perl_remainder(1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->perl_remainder(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# perl_remainder(12, 9) = 3
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
is("$arg1", 12);

$result = WEC::SSL::BigInt::perl_remainder(12, 9);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$result = $arg1->perl_remainder(9);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));


# perl_remainder(-12, 9) = -3
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
is("$arg1", -12);

$result = WEC::SSL::BigInt::perl_remainder(-12, 9);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$result = $arg1->perl_remainder(9);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));


# perl_remainder(12, -9) = 3
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
is("$arg1", 12);

$result = WEC::SSL::BigInt::perl_remainder(12, -9);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$result = $arg1->perl_remainder(-9);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));


# perl_remainder(-12, -9) = -3
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
is("$arg1", -12);

$result = WEC::SSL::BigInt::perl_remainder(-12, -9);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$result = $arg1->perl_remainder(-9);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));


# perl_remainder(581, 3) = 2
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
is("$arg1", 581);

$result = WEC::SSL::BigInt::perl_remainder(581, 3);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$result = $arg1->perl_remainder(3);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));


# perl_remainder(581, -3) = 2
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
is("$arg1", 581);

$result = WEC::SSL::BigInt::perl_remainder(581, -3);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$result = $arg1->perl_remainder(-3);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));


# perl_remainder(-581, 3) = -2
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
is("$arg1", -581);

$result = WEC::SSL::BigInt::perl_remainder(-581, 3);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$result = $arg1->perl_remainder(3);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));


# perl_remainder(-581, -3) = -2
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$result = WEC::SSL::BigInt::perl_remainder($arg2, $arg1, 1);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::perl_remainder($tmp, $arg2, undef);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
is("$arg1", -581);

$result = WEC::SSL::BigInt::perl_remainder(-581, -3);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$result = $arg1->perl_remainder($arg2);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$result = $arg1->perl_remainder(-3);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);

# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(tainted($result));

$arg2->tainted(1);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(tainted($result));

$arg1->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(tainted($result));

$arg2->tainted(0);
$result = WEC::SSL::BigInt::perl_remainder($arg1, $arg2);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));

















"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
