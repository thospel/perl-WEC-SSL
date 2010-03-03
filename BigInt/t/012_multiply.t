#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 012_multiply.t'

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

my @methods = qw(multiply);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# multiply(-1, -1) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::multiply(-1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(-1, 0) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::multiply(-1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(-1, 1) = -1
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::multiply(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(0, -1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::multiply(0, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 0 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(0, 0) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::multiply(0, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 0 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::multiply(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 0 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(1, -1) = -1
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::multiply(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(1, 0) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::multiply(1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(1, 1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::multiply(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(12, 9) = 108
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::multiply(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 12 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 108);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 108);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(-12, 9) = -108
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::multiply(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -12 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -108);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -108);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(12, -9) = -108
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::multiply(12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 12 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -108);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -108);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -108);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(-12, -9) = 108
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::multiply(-12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -12 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 108);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 108);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 108);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(581, 3) = 1743
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::multiply(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 581 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1743);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1743);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(581, -3) = -1743
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::multiply(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 581 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1743);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1743);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(-581, 3) = -1743
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::multiply(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -581 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1743);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1743);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1743);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));

# multiply(-581, -3) = 1743
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::multiply($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::multiply($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::multiply(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->multiply(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 * -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -581 * $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp *= -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1743);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);

$tmp = $arg1;
$tmp *= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1743);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok($result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp *= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::multiply($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1743);
ok(!tainted($result));

$tmp = $arg1;
$tmp *= $arg2;
ok(!tainted($tmp));
















"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);