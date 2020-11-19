#!/usr/bit_length/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 060_bit_length.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL qw(feature_taint);
use WEC::SSL::BigInt;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(bit_length);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $result;

$result = WEC::SSL::BigInt->new(0)->bit_length;
is(ref($result), "");
is($result, 0);

$result = WEC::SSL::BigInt::bit_length(0);
is(ref($result), "");
is($result, 0);

$result = WEC::SSL::BigInt->new(3)->bit_length;
is(ref($result), "");
is($result, 2);

$result = WEC::SSL::BigInt::bit_length(3);
is(ref($result), "");
is($result, 2);

$result = Big->new(-3)->bit_length;
is(ref($result), "");
is($result, 2);

$result = WEC::SSL::BigInt->new(1)->bit_length;
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt::bit_length(1);
is(ref($result), "");
is($result, 1);

$result = Big->new(-1)->bit_length;
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt->new(4)->bit_length;
is($result, 3);

$result = WEC::SSL::BigInt::bit_length(4);
is($result, 3);

$result = WEC::SSL::BigInt->new(-4)->bit_length;
is($result, 3);

$result = WEC::SSL::BigInt::bit_length(-4);
is($result, 3);

my $big = WEC::SSL::BigInt->new("123456789" x 10)->bit_length;
is($big, 296);

$big = WEC::SSL::BigInt::bit_length("123456789" x 10);
is($big, 296);

SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    my $taint = substr("$0$^X", 0, 0);
    my $arg = "5" . $taint;
    $result = WEC::SSL::BigInt->new($arg)->bit_length;
    ok(tainted($result));
    is($result, 3);

    $result = WEC::SSL::BigInt::bit_length($arg);
    ok(tainted($result));
    is($result, 3);
}

"WEC::SSL::BigInt"->import(qw(bit_length));
can_ok(__PACKAGE__, qw(bit_length));
