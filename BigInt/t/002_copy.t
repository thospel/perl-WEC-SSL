#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 02_copy.t'

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok('WEC::SSL::BigInt') };

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(copy);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$result = WEC::SSL::BigInt::copy(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!$result->tainted);

$result = WEC::SSL::BigInt::copy(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);

$result = WEC::SSL::BigInt::copy(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);

$result = WEC::SSL::BigInt::copy(~0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", ~0);
ok(!$result->sensitive);

$tmp = Big->new(-28);
$result = WEC::SSL::BigInt::copy($tmp);
is(ref($result), "WEC::SSL::BigInt");
is("$result", -28);
ok(!$result->sensitive);
ok(!$result->tainted);

$tmp->sensitive(1);
$result = WEC::SSL::BigInt::copy($tmp);
is(ref($result), "WEC::SSL::BigInt");
is("$result", -28);
ok($result->sensitive);
ok(!$result->tainted);

$tmp->tainted(1);
$result = WEC::SSL::BigInt::copy($tmp);
is(ref($result), "WEC::SSL::BigInt");
is("$result", -28);
ok($result->sensitive);
ok($result->tainted);

$tmp->sensitive(0);
$result = WEC::SSL::BigInt::copy($tmp);
is(ref($result), "WEC::SSL::BigInt");
is("$result", -28);
ok(!$result->sensitive);
ok($result->tainted);

$tmp->tainted(0);
$result = WEC::SSL::BigInt::copy($tmp);
is(ref($result), "WEC::SSL::BigInt");
is("$result", -28);
ok(!$result->sensitive);
ok(!$result->tainted);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
