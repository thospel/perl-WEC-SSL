#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 071_mod_subtract.t'
#########################
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL qw(feature_sensitive feature_taint);
use WEC::SSL::BigInt;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(mod_subtract);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($a, $b, $m, $result);

for my $aa (-2, -1, 0, 1, 2) {
    for my $bb (-2, -1, 0, 1, 2, undef) {
        for my $mm (-100, -2, -1, 0, 1, 2, 100) {
            $a = Big->new($aa);
            $b = defined $bb ? Big->new($bb) : $a;
            $m = Big->new($mm);
            # diag("a=$a, b=$b, m=$m\n");
            if ($mm) {
                $result = $a->mod_subtract($b, $m);
                is(ref($result), "WEC::SSL::BigInt");
                is("$result", ($aa-(defined $bb ? $bb : $aa)) % abs $mm);
            } else {
                $result = eval { $a->mod_subtract($b, $m) };
                like($@, qr/^div by zero at /i);
            }
        }
    }
}

for (0..(feature_sensitive() ? 7 : 0)) {
    $a = Big->new(4);
    $a->sensitive(1) if $_ & 1;
    $b = Big->new(8);
    $b->sensitive(1) if $_ & 2;
    $m = Big->new(10);
    $m->sensitive(1) if $_ & 4;
    $result = $a->mod_subtract($b, $m);
    ok(!$result->sensitive ^ !!$_) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    is("$result", 6);
}

for (0..(feature_sensitive() ? 3 : 0)) {
    $a = Big->new(8);
    $a->sensitive(1) if $_ & 1;
    $m = Big->new(10);
    $m->sensitive(1) if $_ & 2;
    $result = $a->mod_subtract($a, $m);
    ok(!$result->sensitive ^ !!$_) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    is("$result", 0);
}

for (0..(feature_taint() ? 7 : 0)) {
    $a = Big->new(4);
    $a->taint(1) if $_ & 1;
    $b = Big->new(8);
    $b->taint(1) if $_ & 2;
    $m = Big->new(10);
    $m->taint(1) if $_ & 4;
    $result = $a->mod_subtract($b, $m);
    ok(!$result->taint ^ !!$_) if feature_taint();
    ok(!$result->sensitive) if feature_sensitive();
    is("$result", 6);
}

for (0..(feature_taint() ? 3 : 0)) {
    $a = Big->new(8);
    $a->taint(1) if $_ & 1;
    $m = Big->new(10);
    $m->taint(1) if $_ & 2;
    $result = $a->mod_subtract($a, $m);
    ok(!$result->taint ^ !!$_) if feature_taint();
    ok(!$result->sensitive) if feature_sensitive();
    is("$result", 0);
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
