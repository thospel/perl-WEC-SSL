#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 006_bin.t'
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

my @methods = qw(from_bin to_bin);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $result;

$result = WEC::SSL::BigInt->from_bin("");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
is($result->to_bin, "");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_bin("\x03");
ok(!$result->sensitive) if feature_sensitive();
is("$result", 3);
is($result->to_bin, "\x03");
is($result->abs_to_bin, "\x03");

$result = Big->from_bin("\x83");
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0x83);
is($result->to_bin, "\x83");
is($result->abs_to_bin, "\x83");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_bin("\x01\x00");
is("$result", 256);
is($result->to_bin, "\x01\x00");
is($result->abs_to_bin, "\x01\x00");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(256);
is("$result", 256);
is($result->to_bin, "\x01\x00");
is($result->abs_to_bin, "\x01\x00");

$result = WEC::SSL::BigInt->new(-256);
is("$result", -256);
is($result->abs_to_bin, "\x01\x00");
$result = eval { $result->to_bin };
like($@, qr/^No bin representation for negative numbers at /i);

my $big = WEC::SSL::BigInt->from_bin(pack("H*", "f83e17daccec61ab9429c707e53e17d8e5bf7d9b72dbfa545ef1f57b73c72870b684045f15"));
isa_ok($big, "WEC::SSL::BigInt");
is("$big", "123456789" x 10);
ok(!$big->sensitive) if feature_sensitive();
is($big->to_bin, pack("H*", "f83e17daccec61ab9429c707e53e17d8e5bf7d9b72dbfa545ef1f57b73c72870b684045f15"));
is($big->abs_to_bin, pack("H*", "f83e17daccec61ab9429c707e53e17d8e5bf7d9b72dbfa545ef1f57b73c72870b684045f15"));

my $taint = substr("$0$^X", 0, 0);
my $arg = "\x01\x00" . $taint;
$result = WEC::SSL::BigInt->from_bin($arg);
ok(tainted($result));
ok($result->taint) if feature_taint();
my $r = "$result";
ok(tainted($r));
is($r, 256);
$r = $result->to_bin;
ok(tainted($r));
is($r, "\x01\x00");
$r = $result->abs_to_bin;
ok(tainted($r));
is($r, "\x01\x00");

SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $result = WEC::SSL::BigInt->from_bin("\x01\x00", 1);
    ok($result->sensitive);
    is("$result", 256);
    is($result->to_bin, "\x01\x00");

    $result = WEC::SSL::BigInt->from_bin("\x01\x00", 0);
    ok(!$result->sensitive);
    is("$result", 256);
    is($result->to_bin, "\x01\x00");
}

"WEC::SSL::BigInt"->import(qw(to_bin));
can_ok(__PACKAGE__, qw(to_bin));
