#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 044_lshift1.t'
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

my @methods = qw(lshift1);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);



















# lshift1(-3) = -6
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::lshift1(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -6);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -6);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -6);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -6);
    ok(!tainted($result));
}

# lshift1(-2) = -4
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::lshift1(-2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -4);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -4);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -4);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -4);
    ok(!tainted($result));
}

# lshift1(-1) = -2
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::lshift1(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(!tainted($result));
}

# lshift1(0) = 0
$arg = Big->new(0);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::lshift1(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));
}

# lshift1(1) = 2
$arg = Big->new(1);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::lshift1(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!tainted($result));
}

# lshift1(2) = 4
$arg = Big->new(2);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::lshift1(2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 4);
    ok(!tainted($result));
}

# lshift1(3) = 6
$arg = Big->new(3);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::lshift1(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 6);
    ok(!tainted($result));
}

# lshift1(9) = 18
$arg = Big->new(9);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::lshift1(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 18);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 18);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 18);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 18);
    ok(!tainted($result));
}

# lshift1(-9) = -18
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::lshift1(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -18);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -18);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -18);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -18);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -18);
    ok(!tainted($result));
}

# lshift1(12) = 24
$arg = Big->new(12);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::lshift1(12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 24);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 24);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 24);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 24);
    ok(!tainted($result));
}

# lshift1(-12) = -24
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::lshift1(-12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -24);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -24);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -24);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -24);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -24);
    ok(!tainted($result));
}

# lshift1(581) = 1162
$arg = Big->new(581);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::lshift1(581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1162);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1162);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1162);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1162);
    ok(!tainted($result));
}

# lshift1(-581) = -1162
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::lshift1($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::lshift1($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::lshift1($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::lshift1(-581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->lshift1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1162);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1162);
    ok($result->sensitive);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1162);
    ok(!$result->sensitive);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1162);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::lshift1($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1162);
    ok(!tainted($result));
}


"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
