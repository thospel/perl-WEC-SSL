#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 009_clear.t'
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

my @methods = qw(clear);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

for (-28, 0, 28) {
    $tmp = $result = WEC::SSL::BigInt->new($_);
    isa_ok($result, "WEC::SSL::BigInt");
    is("$result", $_);
    is("$tmp", $_);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->taint) if feature_taint();

    $result->clear;
    is("$result", 0);
    is("$tmp", 0);
    isa_ok($result, "WEC::SSL::BigInt");
    isa_ok($tmp, "WEC::SSL::BigInt");
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->taint) if feature_taint();

    for (0..(feature_sensitive() ? 1 : -1)) {
        $tmp = $result = Big->new($_);
        $result->sensitive($_ & 1);
        ok($result->sensitive ^ !$_);
        ok($tmp->sensitive ^ !$_);

        $result->clear;
        is("$result", 0);
        is("$tmp", 0);
        isa_ok($result, "Big");
        isa_ok($tmp, "Big");
        ok(!$result->sensitive);
        ok(!$tmp->sensitive);
        ok(!$result->taint) if feature_taint();
        ok(!$tmp->taint) if feature_taint();
    }

    for (0..(feature_taint() ? 1 : -1)) {
        $tmp = $result = Big->new($_);
        $result->taint($_ & 1);
        ok(!$result->sensitive) if feature_sensitive();
        ok(!$tmp->sensitive) if feature_sensitive();
        ok(tainted($result) ^ !$_);
        ok($result->taint ^ !$_);
        ok(!tainted($tmp));
        ok($tmp->taint ^ !$_);

        $result->clear;
        is("$result", 0);
        is("$tmp", 0);
        isa_ok($result, "Big");
        isa_ok($tmp, "Big");
        ok(!$result->sensitive) if feature_sensitive();
        ok(!$tmp->sensitive) if feature_sensitive();
        ok(!tainted($result));
        ok(!$result->taint);
        ok(!tainted($tmp));
        ok(!$tmp->taint);
    }

    eval { WEC::SSL::BigInt::clear($_) };
    like($@, qr/^arg is not a reference at /i);
}
"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
