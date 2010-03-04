#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 001_constants.t'
use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok('WEC::SSL::BigInt') };

my @methods = qw(is_zero is_one ZERO ONE);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}
my $result;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

$result = Big->ZERO;
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->is_zero);
ok(!$result->is_one);
ok(!$result->sensitive);

$result = WEC::SSL::BigInt::ZERO;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->is_zero);
ok(!$result->is_one);
ok(!$result->sensitive);

$result = Big->ONE;
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->is_zero);
ok($result->is_one);
ok(!$result->sensitive);

$result = WEC::SSL::BigInt::ONE;
isa_ok($result, "WEC::SSL::BigInt");
ok(!$result->sensitive);
is("$result", 1);
ok(!$result->is_zero);
ok($result->is_one);

$result = Big->MAX_WORD;
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", (($result/$result*2)**$result->bit_length-1)->to_decimal);
ok(!$result->is_zero);
ok(!$result->is_one);
ok(!$result->sensitive);

$result = WEC::SSL::BigInt::MAX_WORD;
isa_ok($result, "WEC::SSL::BigInt");
ok(!$result->sensitive);
is("$result", (($result/$result*2)**$result->bit_length-1)->to_decimal);
ok(!$result->is_zero);
ok(!$result->is_one);

$result = WEC::SSL::BigInt::PERL_MAX_WORD;
is(ref($result), "");
is($result, 2**WEC::SSL::BigInt::bit_length($result)-1);
ok($result != 0);
ok($result != 1);
ok($result <= ~0);
ok($result <= WEC::SSL::BigInt::MAX_WORD);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
