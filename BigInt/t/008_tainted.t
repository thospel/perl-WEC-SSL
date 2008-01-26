#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 08_tainted.t'

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

my @methods = qw(tainted);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$tmp = $result = WEC::SSL::BigInt->new(-28);
ok(!$result->tainted);
ok(!$result->tainted(1));
ok($result->tainted(1));
ok($result->tainted);
ok(Scalar::Util::tainted($result));
ok(Scalar::Util::tainted($$result));
ok(!Scalar::Util::tainted($tmp));
ok(Scalar::Util::tainted($$tmp));
ok($result->tainted(0));
ok(!$result->tainted(0));
ok(!$result->tainted);
ok(!Scalar::Util::tainted($result));
ok(!Scalar::Util::tainted($$result));
ok(!Scalar::Util::tainted($tmp));
ok(!Scalar::Util::tainted($$tmp));
$result->tainted(28);
ok($result->tainted);
$result->tainted(undef);
ok(!$result->tainted);
$result->tainted([]);
ok($result->tainted);
$result->tainted("0");
ok(!$result->tainted);

$tmp = WEC::SSL::BigInt->new(14);
$tmp->tainted(1);
$result->tainted($tmp);
ok($result->tainted);

$tmp = WEC::SSL::BigInt->new(0);
$tmp->tainted(1);
eval { $result->tainted($tmp) };
like($@, qr/^Turning tainting off using a tainted value at /i);
ok($result->tainted);

is("$result", -28);
ok(!$result->sensitive);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
