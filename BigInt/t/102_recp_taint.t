#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 102_recp_taint.t'
#########################
## no critic (ProhibitUselessNoCritic ProhibitMagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util ();
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL qw(feature_sensitive feature_taint);
use WEC::SSL::Reciprocal;

{
    package Big;
    our @ISA = qw(WEC::SSL::Reciprocal);
}

my @methods = qw(taint);
can_ok("WEC::SSL::Reciprocal", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$tmp = $result = Big->new(-28);
SKIP: {
    skip "Compiled without taint support" if !feature_taint();
    ok(!$result->taint);
    $result->taint(1);
    ok($result->taint);
    ok(Scalar::Util::tainted($result));
    ok(Scalar::Util::tainted($$result));
    ok(!Scalar::Util::tainted($tmp));
    ok(Scalar::Util::tainted($$tmp));
    $result->taint(0);
    ok(!$result->taint);
    ok(!Scalar::Util::tainted($result));
    ok(!Scalar::Util::tainted($$result));
    ok(!Scalar::Util::tainted($tmp));
    ok(!Scalar::Util::tainted($$tmp));
    $result->taint(28);
    ok($result->taint);
    $result->taint(undef);
    ok(!$result->taint);
    $result->taint([]);
    ok($result->taint);
    $result->taint("0");
    ok(!$result->taint);

    $tmp = WEC::SSL::BigInt->new(14);
    $tmp->taint(1);
    $result->taint($tmp);
    ok($result->taint);

    $tmp = WEC::SSL::BigInt->new(0);
    $tmp->taint(1);
    eval { $result->taint($tmp) };
    like($@, qr/^Turning tainting off using a tainted value at /i);
    ok($result->taint);
}

SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    isa_ok($result, "Big");
    ok(!$result->sensitive);
}

"WEC::SSL::Reciprocal"->import(@methods);
can_ok(__PACKAGE__, @methods);
