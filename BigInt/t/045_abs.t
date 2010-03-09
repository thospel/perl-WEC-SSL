#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 045_abs.t'
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

my @methods = qw(abs);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);

# abs(-3) = 3
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::abs(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 3);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 3);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}
# abs(-2) = 2
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::abs(-2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 2);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 2);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(-1) = 1
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::abs(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 1);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(0) = 0
$arg = Big->new(0);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::abs(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 0);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 0);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(1) = 1
$arg = Big->new(1);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::abs(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 1);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(2) = 2
$arg = Big->new(2);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::abs(2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 2);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 2);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(3) = 3
$arg = Big->new(3);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::abs(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 3);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 3);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 3);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(9) = 9
$arg = Big->new(9);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::abs(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 9);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 9);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(-9) = 9
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::abs(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 9);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 9);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 9);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(12) = 12
$arg = Big->new(12);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::abs(12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 12);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 12);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(-12) = 12
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::abs(-12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 12);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 12);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 12);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 12);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(581) = 581
$arg = Big->new(581);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::abs(581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 581);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 581);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

# abs(-581) = 581
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::abs($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::abs($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::abs($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::abs(-581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->abs;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = abs $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 581);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok($result->sensitive);

    $result = abs $arg;
    ok($result->sensitive);
    is("$result", 581);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!$result->sensitive);

    $result = abs $arg;
    ok(!$result->sensitive);
    is("$result", 581);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(tainted($result));

    $result = abs $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::abs($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 581);
    ok(!tainted($result));

    $result = abs $arg;
    ok(!tainted($result));
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
