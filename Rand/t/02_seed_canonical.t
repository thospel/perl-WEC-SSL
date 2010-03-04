#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 02_seed_canonical.t'
use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok('WEC::SSL::Rand') };

my $taint = substr("$^X$0", 0, 0);

# Not much we can do to test effectivity of seeding, but we can at least 
# go through the motions of calling it.

my @methods = qw(seed_canonical);
can_ok("WEC::SSL::Rand", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

WEC::SSL::Rand::seed_canonical("abcd", 3.1);
WEC::SSL::Rand::seed_canonical("abcd");
WEC::SSL::Rand::seed_canonical("");
WEC::SSL::Rand::seed_canonical("abcd", 4);
eval { WEC::SSL::Rand::seed_canonical("abcd", 4.5) };
like($@, qr/^Entropy 4\.5 greater than string length 4 at /i);

my $bytes = chr(252) . chr(253) . chr(254) . chr(255);
utf8::upgrade($bytes);
WEC::SSL::Rand::seed_canonical($bytes, 3.1);
WEC::SSL::Rand::seed_canonical($bytes);
# All 8 bytes making up $bytes internally could be random
# But seed_canonical will use the 4 byte representation of $bytes
WEC::SSL::Rand::seed_canonical($bytes, 4);
# Bigger than 8 is certainly a problem
eval { WEC::SSL::Rand::seed_canonical($bytes, 4.5) };
like($@, qr/^Entropy 4\.5 greater than string length 4 at /i);
ok(utf8::is_utf8($bytes));

$bytes = chr(256) . chr(257) . chr(258) . chr(259);
WEC::SSL::Rand::seed_canonical($bytes, 3.1);
eval { WEC::SSL::Rand::seed_canonical($bytes) };
like($@, qr/^UTF-8 string can\'t be downgraded at /i);
# All 8 bytes making up $bytes internally could be random
# Though in that case some of the possible inputs must be malformed UTF-8
WEC::SSL::Rand::seed_canonical($bytes, 8);
# Bigger than 8 is certainly a problem
eval { WEC::SSL::Rand::seed_canonical($bytes, 8.5) };
like($@, qr/^Entropy 8\.5 greater than string length 8 at /i);
ok(utf8::is_utf8($bytes));

eval { WEC::SSL::Rand::seed_canonical("abcd" . $taint ) };
like($@, qr/^Insecure dependency in seed while running with -T switch at /);
WEC::SSL::Rand::seed_canonical("" . $taint);
eval { WEC::SSL::Rand::seed_canonical("abcd", 3.8 . $taint ) };
like($@, qr/^Insecure dependency in seed while running with -T switch at /);
WEC::SSL::Rand::seed_canonical("abcd", 0 . $taint );

"WEC::SSL::Rand"->import(@methods);
can_ok(__PACKAGE__, @methods);
