#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 103_reciprocal_mod_multiply.t'
#########################
our $VERSION = "1.000";

use strict;
use warnings;
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

my @methods = qw(mod_multiply);
can_ok("WEC::SSL::Reciprocal", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($a, $b, $m, $result);

for my $aa (-2, -1, 0, 1, 2) {
    for my $bb (-2, -1, 0, 1, 2, undef) {
        for my $mm (-100, -2, -1, 1, 2, 100) {
            $a = Big->new($aa);
            $b = defined $bb ? Big->new($bb) : $a;
            $m = WEC::SSL::Reciprocal->new($mm);
            # diag("a=$a, b=$b, m=$m\n");
            if ($mm) {
                $result = $m->mod_multiply($a, $b);
                is(ref($result), "WEC::SSL::BigInt");
                my $mul = ($aa*(defined $bb ? $bb : $aa));
                is("$result",  $mul < 0 ? -(-$mul % abs $mm) : $mul % abs $mm);
            }
        }
    }
}

for (0..(feature_sensitive() ? 7 : 0)) {
    $a = Big->new(4);
    $a->sensitive(1) if $_ & 1;
    $b = Big->new(8);
    $b->sensitive(1) if $_ & 2;
    $m = WEC::SSL::Reciprocal->new(10);
    $m->sensitive(1) if $_ & 4;
    $result = $m->mod_multiply($a, $b);
    ok(!$result->sensitive ^ !!$_) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    is("$result", 2);
}

for (0..(feature_sensitive() ? 3 : 0)) {
    $a = Big->new(8);
    $a->sensitive(1) if $_ & 1;
    $m = WEC::SSL::Reciprocal->new(10);
    $m->sensitive(1) if $_ & 2;
    $result = $m->mod_multiply($a, $a);
    ok(!$result->sensitive ^ !!$_) if feature_sensitive;
    ok(!$result->taint) if feature_taint();
    is("$result", 4);
}

for (0..(feature_taint() ? 7 : 0)) {
    $a = Big->new(4);
    $a->taint(1) if $_ & 1;
    $b = Big->new(8);
    $b->taint(1) if $_ & 2;
    $m = WEC::SSL::Reciprocal->new(10);
    $m->taint(1) if $_ & 4;
    $result = $m->mod_multiply($a, $b);
    ok(!$result->taint ^ !!$_) if feature_taint();
    ok(!$result->sensitive) if feature_sensitive();
    is("$result", 2);
}

for (0..(feature_taint() ? 3 : 0)) {
    $a = Big->new(8);
    $a->taint(1) if $_ & 1;
    $m = WEC::SSL::Reciprocal->new(10);
    $m->taint(1) if $_ & 2;
    $result = $m->mod_multiply($a, $a);
    ok(!$result->taint ^ !!$_) if feature_taint();
    ok(!$result->sensitive) if feature_sensitive();
    is("$result", 4);
}

"WEC::SSL::Reciprocal"->import(@methods);
can_ok(__PACKAGE__, @methods);
