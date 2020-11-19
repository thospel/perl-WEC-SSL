#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 004_hex.t'
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

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(from_hex to_hex to_HEX);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $result;

$result = WEC::SSL::BigInt->from_hex(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
is($result->to_hex, "0");
is($result->to_HEX, "0");
is($result->to_hex(1), "00");
is($result->to_HEX(1), "00");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex(3);
ok(!$result->sensitive) if feature_sensitive();
is("$result", 3);
is($result->to_hex, "3");
is($result->to_HEX, "3");
is($result->to_hex(0), "03");
is($result->to_HEX(0), "03");
is($result->to_hex(1), "03");
is($result->to_HEX(1), "03");

$result = Big->from_hex(-3);
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
is($result->to_hex, "-3");
is($result->to_HEX, "-3");
is($result->to_hex(0), "-03");
is($result->to_HEX(0), "-03");
is($result->to_hex(1), "-03");
is($result->to_HEX(1), "-03");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("C");
is("$result", 12);
is($result->to_hex, "c");
is($result->to_HEX, "C");
is($result->to_hex(0), "0c");
is($result->to_HEX(0), "0C");
is($result->to_hex(1), "0c");
is($result->to_HEX(1), "0C");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("-C");
is("$result", -12);
is($result->to_hex, "-c");
is($result->to_HEX, "-C");
is($result->to_hex(0), "-0c");
is($result->to_HEX(0), "-0C");
is($result->to_hex(1), "-0c");
is($result->to_HEX(1), "-0C");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("     -C");
is("$result", -12);
is($result->to_hex, "-c");
is($result->to_HEX, "-C");
is($result->to_hex(0), "-0c");
is($result->to_HEX(0), "-0C");
is($result->to_hex(1), "-0c");
is($result->to_HEX(1), "-0C");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("     +C");
is("$result", 12);
is($result->to_hex, "c");
is($result->to_HEX, "C");
is($result->to_hex(0), "0c");
is($result->to_HEX(0), "0C");
is($result->to_hex(1), "0c");
is($result->to_HEX(1), "0C");
ok(!$result->sensitive) if feature_sensitive();

my $big = WEC::SSL::BigInt->from_decimal("123456789" x 10);
is("$big", "123456789" x 10);
is($big->to_hex, "f83e17daccec61ab9429c707e53e17d8e5bf7d9b72dbfa545ef1f57b73c72870b684045f15");
is($big->to_HEX, "F83E17DACCEC61AB9429C707E53E17D8E5BF7D9B72DBFA545EF1F57B73C72870B684045F15");
is($big->to_hex(0), "f83e17daccec61ab9429c707e53e17d8e5bf7d9b72dbfa545ef1f57b73c72870b684045f15");
is($big->to_HEX(0), "F83E17DACCEC61AB9429C707E53E17D8E5BF7D9B72DBFA545EF1F57B73C72870B684045F15");
is($big->to_hex(1), "f83e17daccec61ab9429c707e53e17d8e5bf7d9b72dbfa545ef1f57b73c72870b684045f15");
is($big->to_HEX(1), "F83E17DACCEC61AB9429C707E53E17D8E5BF7D9B72DBFA545EF1F57B73C72870B684045F15");
ok(!$big->sensitive) if feature_sensitive();

$big = WEC::SSL::BigInt->from_hex("F83E17DACCEC61AB9429C707e53e17d8e5bf7d9b72dbfa545ef1F57B73C72870B684045F15");
isa_ok($big, "WEC::SSL::BigInt");
is("$big", "123456789" x 10);
ok(!$big->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("1234a", 0);
is("$result", 0x1234a);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("1234a", undef);
is("$result", 0x1234a);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("1234a", 1);
is("$result", 0x1234a);
ok($result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("1234a", "0");
is("$result", 0x1234a);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_hex("1234a", "00");
is("$result", 0x1234a);
ok($result->sensitive) if feature_sensitive();

SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    my $taint = substr("$0$^X", 0, 0);
    my $arg = "ABCD" . $taint;
    $result = WEC::SSL::BigInt->from_hex($arg);
    ok(tainted($result));
    my $r = "$result";
    ok(tainted($r));
    is($r, 0xabcd);
    $r = $result->to_hex;
    ok(tainted($r));
    $r = $result->to_HEX;
    ok(tainted($r));

SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    my $sensitive = "1" . $taint;
    $result = WEC::SSL::BigInt->from_hex("abcd", $sensitive);
    ok(tainted($result));
    ok($result->sensitive);
    is("$result", 0xabcd);
    }
}

$result = eval { WEC::SSL::BigInt->from_hex("") };
like($@, qr/^Hex string is empty at /i);

$result = eval { WEC::SSL::BigInt->from_hex("2aq3a") };
like($@, qr/^Hex string contains non-digit at /i);

"WEC::SSL::BigInt"->import(qw(to_hex to_HEX));
can_ok(__PACKAGE__, qw(to_hex to_HEX));
