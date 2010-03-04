#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 008_taint.t'
use strict;
use warnings;
use Scalar::Util ();
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok("WEC::SSL::BigInt") };

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(taint);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$tmp = $result = WEC::SSL::BigInt->new(-28);
ok(!$result->taint);
ok(!$result->taint(1));
ok($result->taint(1));
ok($result->taint);
ok(Scalar::Util::tainted($result));
ok(Scalar::Util::tainted($$result));
ok(!Scalar::Util::tainted($tmp));
ok(Scalar::Util::tainted($$tmp));
ok($result->taint(0));
ok(!$result->taint(0));
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

is("$result", -28);
ok(!$result->sensitive);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);