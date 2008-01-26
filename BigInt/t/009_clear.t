#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 09_clear.t'

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
    ok(!$result->sensitive);
    ok(!$tmp->sensitive);
    ok(!$result->tainted);
    ok(!$tmp->tainted);

    $result->clear;
    is("$result", 0);
    is("$tmp", 0);
    isa_ok($result, "WEC::SSL::BigInt");
    isa_ok($tmp, "WEC::SSL::BigInt");
    ok(!$result->sensitive);
    ok(!$tmp->sensitive);
    ok(!$result->tainted);
    ok(!$tmp->tainted);

    $tmp = $result = Big->new($_);
    $result->sensitive(1);
    ok($result->sensitive);
    ok($tmp->sensitive);

    $result->clear;
    is("$result", 0);
    is("$tmp", 0);
    isa_ok($result, "Big");
    isa_ok($tmp, "Big");
    ok(!$result->sensitive);
    ok(!$tmp->sensitive);
    ok(!$result->tainted);
    ok(!$tmp->tainted);

    $tmp = $result = Big->new($_);
    $result->tainted(1);
    ok(!$result->sensitive);
    ok(!$tmp->sensitive);
    ok($result->tainted);
    ok($tmp->tainted);

    $result->clear;
    is("$result", 0);
    is("$tmp", 0);
    isa_ok($result, "Big");
    isa_ok($tmp, "Big");
    ok(!$result->sensitive);
    ok(!$tmp->sensitive);
    ok(!$result->tainted);
    ok(!$tmp->tainted);

    eval { WEC::SSL::BigInt::clear($_) };
    like($@, qr/^arg is not a reference at /i);
}
"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
