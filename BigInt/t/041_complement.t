#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 041_complement.t'
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

my @methods = qw(complement);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);

# complement(-3) = 2
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::complement(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", 2);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 2);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", 2);
}

# Check taint propagation
$arg->taint(1);
$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$result = ~ $arg;
ok(tainted($result));
$arg->taint(0);
$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!tainted($result));

$result = ~ $arg;
ok(!tainted($result));

# complement(-2) = 1
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::complement(-2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", 1);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 1);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(-1) = 0
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::complement(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", 0);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", 0);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 0);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(0) = -1
$arg = Big->new(0);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::complement(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", -1);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", -1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -1);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(1) = -2
$arg = Big->new(1);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::complement(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", -2);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", -2);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -2);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(2) = -3
$arg = Big->new(2);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::complement(2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", -3);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", -3);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -3);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(3) = -4
$arg = Big->new(3);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::complement(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -4);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -4);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", -4);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -4);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", -4);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -4);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -4);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(9) = -10
$arg = Big->new(9);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -10);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -10);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -10);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::complement(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -10);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -10);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -10);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -10);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", -10);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -10);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", -10);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -10);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -10);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(-9) = 8
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 8);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 8);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 8);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::complement(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 8);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 8);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 8);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 8);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", 8);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 8);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", 8);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 8);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 8);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(12) = -13
$arg = Big->new(12);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -13);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -13);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -13);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::complement(12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -13);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -13);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -13);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -13);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", -13);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -13);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", -13);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -13);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -13);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(-12) = 11
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 11);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 11);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 11);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::complement(-12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 11);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 11);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 11);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 11);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", 11);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 11);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", 11);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 11);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 11);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(581) = -582
$arg = Big->new(581);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -582);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -582);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -582);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::complement(581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -582);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -582);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -582);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -582);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", -582);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -582);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", -582);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -582);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", -582);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

# complement(-581) = 580
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::complement($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 580);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = WEC::SSL::BigInt::complement($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 580);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$tmp = $arg->copy;
$result = WEC::SSL::BigInt::complement($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 580);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::complement(-581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 580);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = $arg->complement;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 580);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

$result = ~ $arg;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 580);
ok(!$result->sensitive) if feature_sensitive();
ok(!tainted($result));

# Check sensitive propagation
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 580);
    ok($result->sensitive);

    $result = ~ $arg;
    ok($result->sensitive);
    is("$result", 580);
    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 580);
    ok(!$result->sensitive);

    $result = ~ $arg;
    ok(!$result->sensitive);
    is("$result", 580);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 580);
    ok(tainted($result));

    $result = ~ $arg;
    ok(tainted($result));
    $arg->taint(0);
    $result = WEC::SSL::BigInt::complement($arg);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", 580);
    ok(!tainted($result));

    $result = ~ $arg;
    ok(!tainted($result));
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
