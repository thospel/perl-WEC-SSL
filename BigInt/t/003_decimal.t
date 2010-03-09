#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 003_decimal.t'
use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL qw(feature_sensitive feature_taint);
use WEC::SSL::BigInt;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(from_decimal to_decimal to_integer abs_to_integer);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $result;

$result = WEC::SSL::BigInt->from_decimal(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
is($result->to_decimal, 0);
ok($result->is_zero);
ok(!$result->is_one);
is($result->to_integer, 0);
is($result->abs_to_integer, 0);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_decimal("-0");
is("$result", 0);
is($result->to_decimal, 0);
ok($result->is_zero);
ok(!$result->is_one);
is($result->to_integer, 0);
is($result->abs_to_integer, 0);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_decimal(1);
is("$result", 1);
is($result->to_decimal, 1);
ok(!$result->is_zero);
ok($result->is_one);
is($result->to_integer, 1);
is($result->abs_to_integer, 1);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_decimal(3);
is("$result", 3);
is($result->to_decimal, 3);
is($result->to_integer, 3);
ok(!$result->is_zero);
ok(!$result->is_one);
is($result->abs_to_integer, 3);
ok(!$result->sensitive) if feature_sensitive();

$result = Big->from_decimal(-3);
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
is($result->to_decimal, -3);
ok(!$result->sensitive) if feature_sensitive();
is($result->to_integer, -3);
is($result->abs_to_integer, 3);

$result = WEC::SSL::BigInt->from_decimal("+3");
ok(!$result->sensitive) if feature_sensitive();
is("$result", 3);
is($result->to_decimal, 3);
is($result->to_integer, 3);
is($result->abs_to_integer, 3);

my $big = WEC::SSL::BigInt->from_decimal("123456789" x 10);
isa_ok($big, "WEC::SSL::BigInt");
is("$big", "123456789" x 10);
ok(!$big->sensitive) if feature_sensitive();
is($big->to_decimal, "123456789" x 10);
eval { $big->to_integer };
ok($@ =~ /value out of range/i);
eval { $big->abs_to_integer };
ok($@ =~ /value out of range/i);

$result = eval { WEC::SSL::BigInt->from_decimal("abc") };
ok($@ =~ /^Decimal string contains non-digit/i);

$result = eval { WEC::SSL::BigInt->from_decimal("abc123") };
ok($@ =~ /^Decimal string contains non-digit/i);

$result = eval { WEC::SSL::BigInt->from_decimal("123abc") };
ok($@ =~ /^Decimal string contains non-digit/i);

$result = eval { WEC::SSL::BigInt->from_decimal("1e9") };
ok($@ =~ /^Decimal string contains non-digit/i);

$result = eval { WEC::SSL::BigInt->from_decimal("") };
like($@, qr/^Decimal string is empty at /i);

$result = WEC::SSL::BigInt->from_decimal("   1234");
is("$result", 1234);
is($result->to_decimal, 1234);
ok(!$result->sensitive) if feature_sensitive();
is($result->to_integer, 1234);
is($result->abs_to_integer, 1234);

$result = WEC::SSL::BigInt->from_decimal("   -1234");
is("$result", -1234);
is($result->to_decimal, -1234);
ok(!$result->sensitive) if feature_sensitive();
is($result->to_integer, -1234);
is($result->abs_to_integer, 1234);

my $copy = WEC::SSL::BigInt->from_decimal($result);
ok(!$result->sensitive) if feature_sensitive();
ok(!$copy->sensitive) if feature_sensitive();
is("$copy", -1234);
is($copy->to_decimal, -1234);
is("-" ^ $copy->to_decimal, "\x001234", "result is a string, not a number");
is($copy->to_integer, -1234);
is($copy->abs_to_integer, 1234);
is(1 ^ $copy->to_integer, 1 ^ -1234, "result is a number, not a string");
is(1 ^ $copy->abs_to_integer, 1235, "result is a number, not a string");
$result->abs_bit(0, 1);
is("$result", -1235, "Succesfully changed original");
is("$copy",   -1234, "Changing original does not change copy");

SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $result->sensitive(1);
    ok($result->sensitive);
    $copy = WEC::SSL::BigInt->from_decimal($result);
    is("$copy",   -1235, "Copy has same value as original");
    ok($result->sensitive);
    ok(!$copy->sensitive);
    $result->abs_bit(0, 0);
    is("$result", -1234, "Succesfully changed original");
    is("$copy",   -1235, "Changing original does not change copy");
}

$result = WEC::SSL::BigInt->from_decimal("1234", 0);
is("$result", 1234);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_decimal("1234", undef);
is("$result", 1234);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_decimal("1234", 1);
is("$result", 1234);
ok($result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_decimal("1234", "0");
is("$result", 1234);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_decimal("1234", "00");
is("$result", 1234);
ok($result->sensitive) if feature_sensitive();

my $taint = substr("$0$^X", 0, 0);
my $arg = "1234" . $taint;
$result = WEC::SSL::BigInt->from_decimal($arg);
ok(tainted($result));
my $r = "$result";
ok(tainted($r));
is($r, 1234);
$r = $result->to_decimal;
ok(tainted($r));
$r = $result->to_integer;
ok(tainted($r));
$r = $result->abs_to_integer;
ok(tainted($r));

SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();
    skip "Compiled without taint support" if !feature_taint();

    my $sensitive = "1" . $taint;
    $result = WEC::SSL::BigInt->from_decimal("1234", $sensitive);
    ok(tainted($result));
    ok($result->sensitive);
    is("$result", 1234);
}

"WEC::SSL::BigInt"->import(qw(to_decimal to_integer abs_to_integer));
can_ok(__PACKAGE__, qw(to_decimal to_integer abs_to_integer));
