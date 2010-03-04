#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 082_pseudo_rand.t'
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

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(pseudo_rand);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($val, $result);

$val = Big->new(1);
$result = $val->pseudo_rand;
is("$result", 0);
ok(!$result->sensitive);
ok(!$result->taint);

$val = Big->new(0);
$result = eval { $val->pseudo_rand };
like($@, qr/^invalid range at /i);

$val = Big->new(-1);
$result = eval { $val->pseudo_rand };
like($@, qr/^invalid range at /i);

$val = Big->new(5);
my %results;
$results{$val->pseudo_rand}++ for 1..1000;

# Check reasonable spread (extremely small chance of random failure)
is_deeply([sort {$a <=> $b } keys %results], [0..$val-1]);
for (0..$val-1) {
    ok($results{$_} > 1000/$val/2);
}

$val = Big->new(5);
$val->sensitive(1);
$result = $val->pseudo_rand;
ok($result < $val);
ok($result->sensitive);
ok(!$result->taint);

$val = Big->new(5);
$val->taint(1);
$result = $val->pseudo_rand;
ok($result < $val);
ok(!$result->sensitive);
ok($result->taint);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
