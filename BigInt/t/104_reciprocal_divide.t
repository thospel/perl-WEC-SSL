#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 104_reciprocal_divide.t'
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
use WEC::SSL::Reciprocal;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(divide);
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
        # diag("a=$a, b=$b, m=$m\n");
        if ($mm) {
            $result = $m->divide($a);
            is(ref($result), "WEC::SSL::BigInt");
            is("$result",  int($aa / $mm));

            my ($q, $r) = $m->divide($a);
            is(ref($q), "WEC::SSL::BigInt");
            is(ref($r), "WEC::SSL::BigInt");
            is("$q",  int($aa / $mm));
            is("$r",  $aa-int($aa / $mm)*$mm);
        }
    }
}

for (0..(feature_sensitive() ? 3 : 0)) {
    $a = Big->new(17);
    $a->sensitive(1) if $_ & 1;
    $m = WEC::SSL::Reciprocal->new(7);
    $m->sensitive(1) if $_ & 2;
    $result = $m->divide($a);
    ok(!$result->sensitive ^ !!$_) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    is("$result", 2);

    my ($q, $r) = $m->divide($a);
    ok(!$q->sensitive ^ !!$_) if feature_sensitive();
    ok(!$r->sensitive ^ !!$_) if feature_sensitive();
    ok(!$q->taint) if feature_taint();
    ok(!$r->taint) if feature_taint();
    is("$q", 2);
    is("$r", 3);
}

for (0..(feature_taint() ? 3 : 0)) {
    $a = Big->new(17);
    $a->taint(1) if $_ & 1;
    $m = WEC::SSL::Reciprocal->new(7);
    $m->taint(1) if $_ & 2;
    $result = $m->divide($a);
    ok(!$result->taint ^ !!$_) if feature_taint();
    ok(!$result->sensitive) if feature_sensitive();
    is("$result", 2);

    my ($q, $r) = $m->divide($a);
    ok(!$q->sensitive) if feature_sensitive();
    ok(!$r->sensitive) if feature_sensitive();
    ok(!$q->taint ^ !!$_) if feature_taint();
    ok(!$r->taint ^ !!$_) if feature_taint();
    is("$q", 2);
    is("$r", 3);
}

"WEC::SSL::Reciprocal"->import(@methods);
can_ok(__PACKAGE__, @methods);
