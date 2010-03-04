#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 100_reciprocal_new.t'
use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN {
    use_ok("WEC::SSL::BigInt");
    use_ok("WEC::SSL::Reciprocal");
};

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my ($rec, $val);

my $taint = substr("$^X$0", 0, 0);

for my $n (-25, -1, 1, 25, "123456789" x 100) {
    $rec = WEC::SSL::Reciprocal->new($n);
    ok(!$rec->sensitive);
    ok(!$rec->taint);

    $val = Big->new($n);
    $val->sensitive(1);
    $rec = WEC::SSL::Reciprocal->new($val);
    ok($rec->sensitive);
    ok(!$rec->taint);

    $val = Big->new($n . $taint);
    $rec = WEC::SSL::Reciprocal->new($val);
    ok(!$rec->sensitive);
    ok($rec->taint);

    $val = Big->new($n . $taint);
    $val->sensitive(1);
    $rec = WEC::SSL::Reciprocal->new($val);
    ok($rec->sensitive);
    ok($rec->taint);
}

$rec = eval { WEC::SSL::Reciprocal->new(0) };
like($@, qr/^Reciprocal of 0 at /);
