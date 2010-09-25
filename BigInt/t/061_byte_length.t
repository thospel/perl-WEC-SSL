#!/usr/byte_length/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 061_byte_length.t'
#########################
## no critic (ProhibitUselessNoCritic ProhibitMagicNumbers)
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

my @methods = qw(byte_length);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $result;

$result = WEC::SSL::BigInt->new(0)->byte_length;
is(ref($result), "");
is($result, 0);

$result = WEC::SSL::BigInt::byte_length(0);
is(ref($result), "");
is($result, 0);

$result = WEC::SSL::BigInt->new(1)->byte_length;
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt::byte_length(1);
is(ref($result), "");
is($result, 1);

$result = Big->new(-1)->byte_length;
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt->new(3)->byte_length;
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt::byte_length(3);
is(ref($result), "");
is($result, 1);

$result = Big->new(-3)->byte_length;
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt::byte_length(-3);
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt->new(255)->byte_length;
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt::byte_length(255);
is(ref($result), "");
is($result, 1);

$result = Big->new(-255)->byte_length;
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt::byte_length(-255);
is(ref($result), "");
is($result, 1);

$result = WEC::SSL::BigInt->new(256)->byte_length;
is($result, 2);

$result = WEC::SSL::BigInt::byte_length(256);
is($result, 2);

$result = WEC::SSL::BigInt->new(-256)->byte_length;
is($result, 2);

$result = WEC::SSL::BigInt::byte_length(-256);
is($result, 2);

my $big = WEC::SSL::BigInt->new("123456789" x 10)->byte_length;
is($big, 37);

$big = WEC::SSL::BigInt::byte_length("123456789" x 10);
is($big, 37);

$big = WEC::SSL::BigInt->new("123456789" x 10);
$big /=2;
$result = $big->byte_length;
is($result, 37);
$result = WEC::SSL::BigInt::byte_length($big);
is($result, 37);

SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    my $taint = substr("$0$^X", 0, 0);
    my $arg = "257" . $taint;
    $result = WEC::SSL::BigInt->new($arg)->byte_length;
    ok(tainted($result));
    is($result, 2);

    $result = WEC::SSL::BigInt::byte_length($arg);
    ok(tainted($result));
    is($result, 2);
}

"WEC::SSL::BigInt"->import(qw(byte_length));
can_ok(__PACKAGE__, qw(byte_length));
