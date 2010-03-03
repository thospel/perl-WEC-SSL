#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 70_mod_multiply.t'

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

my @methods = qw(mod_multiply);
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
                $result = $a->mod_multiply($b, $m);
                is(ref($result), "WEC::SSL::BigInt");
                is("$result", ($aa*(defined $bb ? $bb : $aa)) % abs $mm);
            } else {
                $result = eval { $a->mod_multiply($b, $m) };
                like($@, qr/^div by zero at /i);
            }
        }
    }
}

for (0..7) {
    $a = Big->new(4);
    $a->sensitive(1) if $_ & 1;
    $b = Big->new(8);
    $b->sensitive(1) if $_ & 2;
    $m = Big->new(10);
    $m->sensitive(1) if $_ & 4;
    $result = $a->mod_multiply($b, $m);
    ok(!$result->sensitive ^ !!$_);
    ok(!$result->tainted);
    is("$result", 2);
}

for (0..3) {
    $a = Big->new(8);
    $a->sensitive(1) if $_ & 1;
    $m = Big->new(10);
    $m->sensitive(1) if $_ & 2;
    $result = $a->mod_multiply($a, $m);
    ok(!$result->sensitive ^ !!$_);
    ok(!$result->tainted);
    is("$result", 4);
}

for (0..7) {
    $a = Big->new(4);
    $a->tainted(1) if $_ & 1;
    $b = Big->new(8);
    $b->tainted(1) if $_ & 2;
    $m = Big->new(10);
    $m->tainted(1) if $_ & 4;
    $result = $a->mod_multiply($b, $m);
    ok(!$result->tainted ^ !!$_);
    ok(!$result->sensitive);
    is("$result", 2);
}

for (0..3) {
    $a = Big->new(8);
    $a->tainted(1) if $_ & 1;
    $m = Big->new(10);
    $m->tainted(1) if $_ & 2;
    $result = $a->mod_multiply($a, $m);
    ok(!$result->tainted ^ !!$_);
    ok(!$result->sensitive);
    is("$result", 4);
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);