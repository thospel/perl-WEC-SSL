#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 105_reciprocal_remainder.t'

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

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(remainder);
can_ok("WEC::SSL::Reciprocal", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($a, $b, $m, $result);

for my $aa (-2, -1, 0, 1, 2) {
        for my $mm (-100, -2, -1, 1, 2, 100) {
            $a = Big->new($aa);
            $m = WEC::SSL::Reciprocal->new($mm);
            # diag("a=$aa, m=$mm\n");
            if ($mm) {
                $result = $m->remainder($a);
                is(ref($result), "WEC::SSL::BigInt");
                is("$result",  (abs($aa) % abs $mm)* ($aa < 0 ? -1 : 1));
            }
        }
}

for (0..3) {
    $a = Big->new(17);
    $a->sensitive(1) if $_ & 1;
    $m = WEC::SSL::Reciprocal->new(7);
    $m->sensitive(1) if $_ & 2;
    $result = $m->remainder($a);
    ok(!$result->sensitive ^ !!$_);
    ok(!$result->tainted);
    is("$result", 3);
}

for (0..3) {
    $a = Big->new(17);
    $a->tainted(1) if $_ & 1;
    $m = WEC::SSL::Reciprocal->new(7);
    $m->tainted(1) if $_ & 2;
    $result = $m->remainder($a);
    ok(!$result->tainted ^ !!$_);
    ok(!$result->sensitive);
    is("$result", 3);
}

"WEC::SSL::Reciprocal"->import(@methods);
can_ok(__PACKAGE__, @methods);
