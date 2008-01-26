#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 101_reciprocal_sensitive.t'

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok("WEC::SSL::Reciprocal") };

{
    package Big;
    our @ISA = qw(WEC::SSL::Reciprocal);
}

my @methods = qw(sensitive);
can_ok("WEC::SSL::Reciprocal", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$tmp = $result = Big->new(-28);
ok(!$result->sensitive);
ok(!$tmp->sensitive);
$result->sensitive(1);
ok($result->sensitive);
ok($tmp->sensitive);
$result->sensitive(0);
ok(!$result->sensitive);
$result->sensitive(28);
ok($result->sensitive);
$result->sensitive(undef);
ok(!$result->sensitive);
$result->sensitive([]);
ok($result->sensitive);
$result->sensitive("0");
ok(!$result->sensitive);

$tmp = WEC::SSL::BigInt->new(14);
$tmp->sensitive(1);
$result->sensitive($tmp);
ok($result->sensitive);

$tmp = WEC::SSL::BigInt->new(0);
$tmp->sensitive(1);
eval { $result->sensitive($tmp) };
like($@, qr/^Turning sensitivity off using a sensitive value at /i);
ok($result->sensitive);

isa_ok($result, "Big");
ok(!$result->tainted);

"WEC::SSL::Reciprocal"->import(@methods);
can_ok(__PACKAGE__, @methods);
