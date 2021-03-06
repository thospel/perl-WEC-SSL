#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 04_bytes.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Rand
;

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(bytes);
can_ok("WEC::SSL::Rand", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

# Fake seeding the PRNG
WEC::SSL::Rand::seed("1" x 1024);

my $str = WEC::SSL::Rand::bytes(3.1);
is(length $str, 3);
ok(!tainted($str));

$str = WEC::SSL::Rand::bytes(0);
is($str, "");
ok(!tainted($str));

$str = eval { WEC::SSL::Rand::bytes(-1) };
like($@, qr/^length -1 is negative at /i);

my @counts;
for (1..1000) {
    my $str = unpack("B*", WEC::SSL::Rand::bytes(2));
    die "Weird result $str" if $str !~ /^[01]{16}\z/;
    $counts[$_] += substr($str, $_, 1) for 0..15;
}
for (0..15) {
    ok($counts[$_] > 1000/2/2);
}

$str = WEC::SSL::Rand::bytes(4 . $taint);
is(length $str, 4);
ok(tainted($str));

"WEC::SSL::Rand"->import(@methods);
can_ok(__PACKAGE__, @methods);
