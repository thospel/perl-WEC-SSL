#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 030_abs_cmp.t'
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

my @methods = qw(abs_cmp);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# abs_cmp(-1, -1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", -1);

$result = WEC::SSL::BigInt::abs_cmp(-1, -1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp(-1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# abs_cmp(-1, 0) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", -1);

$result = WEC::SSL::BigInt::abs_cmp(-1, 0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(-1, 1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", -1);

$result = WEC::SSL::BigInt::abs_cmp(-1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# abs_cmp(0, -1) = -1
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", 0);

$result = WEC::SSL::BigInt::abs_cmp(0, -1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->abs_cmp(-1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));


# abs_cmp(0, 0) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 0);

$result = WEC::SSL::BigInt::abs_cmp(0, 0);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp(0);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# abs_cmp(0, 1) = -1
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg1", 0);

$result = WEC::SSL::BigInt::abs_cmp(0, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg1->abs_cmp(1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));


# abs_cmp(1, -1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 1);

$result = WEC::SSL::BigInt::abs_cmp(1, -1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp(-1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# abs_cmp(1, 0) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 1);

$result = WEC::SSL::BigInt::abs_cmp(1, 0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(0);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(1, 1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg1", 1);

$result = WEC::SSL::BigInt::abs_cmp(1, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg1->abs_cmp(1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));


# abs_cmp(12, 9) = 1
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 12);

$result = WEC::SSL::BigInt::abs_cmp(12, 9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(-12, 9) = 1
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", -12);

$result = WEC::SSL::BigInt::abs_cmp(-12, 9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(12, -9) = 1
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 12);

$result = WEC::SSL::BigInt::abs_cmp(12, -9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(-9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(-12, -9) = 1
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", -12);

$result = WEC::SSL::BigInt::abs_cmp(-12, -9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(-9);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(581, 3) = 1
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 581);

$result = WEC::SSL::BigInt::abs_cmp(581, 3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(581, -3) = 1
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", 581);

$result = WEC::SSL::BigInt::abs_cmp(581, -3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(-3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(-581, 3) = 1
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", -581);

$result = WEC::SSL::BigInt::abs_cmp(-581, 3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));


# abs_cmp(-581, -3) = 1
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs_cmp($arg2, $arg1, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::abs_cmp($tmp, $arg2, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg1", -581);

$result = WEC::SSL::BigInt::abs_cmp(-581, -3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp($arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg1->abs_cmp(-3);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
# Check operation under sensitivity
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg1->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

$arg2->sensitive(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);

# Check taint propagation
$arg1->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(1);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg1->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(tainted($result));

$arg2->taint(0);
$result = WEC::SSL::BigInt::abs_cmp($arg1, $arg2);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

















"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
