#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 005_mpi.t'
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

my @methods = qw(from_mpi to_mpi);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $result;

$result = WEC::SSL::BigInt->from_mpi(pack("N", 0));
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
is($result->to_mpi, pack("N", 0));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_mpi(pack("NC", 1, 3));
ok(!$result->sensitive) if feature_sensitive();
is("$result", 3);
is($result->to_mpi, pack("NC", 1, 3));

$result = Big->from_mpi(pack("NC", 1, 0x83));
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
is($result->to_mpi, pack("NC", 1, 0x83));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_mpi(pack("NCC", 2, 0, 0xc8));
is("$result", 200);
is($result->to_mpi, pack("NCC", 2, 0, 0xc8));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_mpi(pack("NCC", 2, 0x80, 0xc8));
is("$result", -200);
is($result->to_mpi, pack("NCC", 2, 0x80, 0xc8));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->from_mpi(pack("NC", 1, 0xc8));
is("$result", -72);
is($result->to_mpi, pack("NC", 1, 0xc8));
ok(!$result->sensitive) if feature_sensitive();

$result = eval { WEC::SSL::BigInt->from_mpi("123") };
like($@, qr/^invalid length at /i);

$result = eval { WEC::SSL::BigInt->from_mpi(pack("NC*", 1, 0x05, 0x08)) };
like($@, qr/^encoding error at /i);

my $big = WEC::SSL::BigInt->from_mpi(pack("NH*", 0x26, "00f83e17daccec61ab9429c707e53e17d8e5bf7d9b72dbfa545ef1f57b73c72870b684045f15"));
isa_ok($big, "WEC::SSL::BigInt");
is("$big", "123456789" x 10);
ok(!$big->sensitive) if feature_sensitive();

my $taint = substr("$0$^X", 0, 0);
my $arg = pack("NCC", 2, 0, 0xc8) . $taint;
$result = WEC::SSL::BigInt->from_mpi($arg);
ok(tainted($result));
ok($result->taint) if feature_taint();

my $r = "$result";
ok(tainted($r));
is($r, 200);
$r = $result->to_mpi;
ok(tainted($r));
is($r, pack("NCC", 2, 0, 0xc8));

$result = WEC::SSL::BigInt->from_mpi(pack("NC", 1, 3), 1);
ok($result->sensitive) if feature_sensitive();
is("$result", 3);
is($result->to_mpi, pack("NC", 1, 3));

$result = WEC::SSL::BigInt->from_mpi(pack("NC", 1, 3), 0);
ok(!$result->sensitive) if feature_sensitive();
is("$result", 3);
is($result->to_mpi, pack("NC", 1, 3));

"WEC::SSL::BigInt"->import(qw(to_mpi));
can_ok(__PACKAGE__, qw(to_mpi));
