#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 047_int.t'
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

my @methods = qw(int);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);

# int(-3) = -3
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::int(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok(!$result->sensitive);
}

SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    # Check taint propagation
    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok(!tainted($result));
}

# int(-2) = -2
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::int(-2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(!tainted($result));
}

# int(-1) = -1
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::int(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!tainted($result));
}

# int(0) = 0
$arg = Big->new(0);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::int(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# int(1) = 1
$arg = Big->new(1);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::int(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!tainted($result));
}

# int(2) = 2
$arg = Big->new(2);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::int(2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!tainted($result));
}

# int(3) = 3
$arg = Big->new(3);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::int(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(!tainted($result));
}

# int(9) = 9
$arg = Big->new(9);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::int(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(!tainted($result));
}

# int(-9) = -9
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::int(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -9);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -9);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -9);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -9);
    ok(!tainted($result));
}

# int(12) = 12
$arg = Big->new(12);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::int(12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!tainted($result));
}

# int(-12) = -12
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::int(-12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -12);
    ok(!tainted($result));
}

# int(581) = 581
$arg = Big->new(581);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::int(581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!tainted($result));
}

# int(-581) = -581
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::int($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::int($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::int($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::int(-581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->int;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::int($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -581);
    ok(!tainted($result));
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
