#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 047_to_integer.t'
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

my @methods = qw(to_integer);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);



















# to_integer(-3) = -3
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
is("$arg", -3);

$result = WEC::SSL::BigInt::to_integer(-3);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, -3);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -3);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -3);
}

# Check taint propagation
$arg->taint(1);
$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, -3);
ok(tainted($result));

$arg->taint(0);
$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, -3);
ok(!tainted($result));


# to_integer(-2) = -2
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
is("$arg", -2);

$result = WEC::SSL::BigInt::to_integer(-2);
is(ref($result), "");
is($result, -2);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, -2);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -2);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -2);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -2);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -2);
    ok(!tainted($result));
}

# to_integer(-1) = -1
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
is("$arg", -1);

$result = WEC::SSL::BigInt::to_integer(-1);
is(ref($result), "");
is($result, -1);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, -1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -1);
    ok(!tainted($result));
}

# to_integer(0) = 0
$arg = Big->new(0);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
is("$arg", 0);

$result = WEC::SSL::BigInt::to_integer(0);
is(ref($result), "");
is($result, 0);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, 0);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 0);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 0);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 0);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 0);
    ok(!tainted($result));
}

# to_integer(1) = 1
$arg = Big->new(1);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
is("$arg", 1);

$result = WEC::SSL::BigInt::to_integer(1);
is(ref($result), "");
is($result, 1);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, 1);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 1);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 1);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 1);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 1);
    ok(!tainted($result));
}

# to_integer(2) = 2
$arg = Big->new(2);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
is("$arg", 2);

$result = WEC::SSL::BigInt::to_integer(2);
is(ref($result), "");
is($result, 2);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, 2);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 2);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 2);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 2);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 2);
    ok(!tainted($result));
}

# to_integer(3) = 3
$arg = Big->new(3);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
is("$arg", 3);

$result = WEC::SSL::BigInt::to_integer(3);
is(ref($result), "");
is($result, 3);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, 3);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 3);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 3);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 3);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 3);
    ok(!tainted($result));
}

# to_integer(9) = 9
$arg = Big->new(9);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, 9);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, 9);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, 9);
ok(!tainted($result));
is("$arg", 9);

$result = WEC::SSL::BigInt::to_integer(9);
is(ref($result), "");
is($result, 9);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, 9);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 9);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 9);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 9);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 9);
    ok(!tainted($result));
}

# to_integer(-9) = -9
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, -9);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, -9);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, -9);
ok(!tainted($result));
is("$arg", -9);

$result = WEC::SSL::BigInt::to_integer(-9);
is(ref($result), "");
is($result, -9);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, -9);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -9);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -9);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -9);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -9);
    ok(!tainted($result));
}

# to_integer(12) = 12
$arg = Big->new(12);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, 12);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, 12);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, 12);
ok(!tainted($result));
is("$arg", 12);

$result = WEC::SSL::BigInt::to_integer(12);
is(ref($result), "");
is($result, 12);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, 12);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 12);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 12);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 12);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 12);
    ok(!tainted($result));
}

# to_integer(-12) = -12
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, -12);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, -12);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, -12);
ok(!tainted($result));
is("$arg", -12);

$result = WEC::SSL::BigInt::to_integer(-12);
is(ref($result), "");
is($result, -12);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, -12);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -12);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -12);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -12);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -12);
    ok(!tainted($result));
}

# to_integer(581) = 581
$arg = Big->new(581);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, 581);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, 581);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, 581);
ok(!tainted($result));
is("$arg", 581);

$result = WEC::SSL::BigInt::to_integer(581);
is(ref($result), "");
is($result, 581);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, 581);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 581);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 581);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 581);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, 581);
    ok(!tainted($result));
}

# to_integer(-581) = -581
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::to_integer($arg);
is(ref($result), "");
is($result, -581);
ok(!tainted($result));
$result = WEC::SSL::BigInt::to_integer($arg, undef, 1);
is(ref($result), "");
is($result, -581);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::to_integer($tmp, undef, undef);
is(ref($result), "");
is($result, -581);
ok(!tainted($result));
is("$arg", -581);

$result = WEC::SSL::BigInt::to_integer(-581);
is(ref($result), "");
is($result, -581);
ok(!tainted($result));
$result = $arg->to_integer;
is(ref($result), "");
is($result, -581);
ok(!tainted($result));

# Check operation under sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $arg->sensitive(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -581);

    $arg->sensitive(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -581);
}

# Check taint propagation
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $arg->taint(1);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -581);
    ok(tainted($result));

    $arg->taint(0);
    $result = WEC::SSL::BigInt::to_integer($arg);
    is(ref($result), "");
    is($result, -581);
    ok(!tainted($result));
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
