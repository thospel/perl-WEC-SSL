#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 81_rand_prime.t'

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { 
    use_ok("WEC::SSL::BigInt");
    use_ok("WEC::SSL::Rand");
};

# Fake seeding the PRNG
WEC::SSL::Rand::seed("1" x 1024);

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(rand_prime);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $val;

$val = Big->rand_prime(bit_length => 256);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok(!$val->sensitive);
ok(!$val->tainted);

$val = Big->rand_prime(bits => 256);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);

eval { Big->rand_prime };
like($@, qr/^No bits argument at /i);
eval { Big->rand_prime(bit_length => -1) };
like($@, qr/^Negative number of bits at /i);
eval { Big->rand_prime(bit_length => 0) };
like($@, qr/^There are no 0 bit primes at /i);
eval { Big->rand_prime(bit_length => 1) };
like($@, qr/^There are no 1 bit primes at /i);
eval { Big->rand_prime(bit_length => 2**64) };
like($@, qr/^Bits .*out of range at /i);
eval { Big->rand_prime(vroem => 1) };
like($@, qr/^Unknown option 'vroem' at /i);
eval { Big->rand_prime("vroem") };
like($@, qr/^Odd number of arguments at /i);

$val = Big->rand_prime(bits => 256, modulus => 256);
isa_ok($val, "Big");
is($val->bit_length, 256);
is(($val % 256)->to_decimal, 1);
ok($val->is_prime);

$val = Big->rand_prime(bits => 256, "mod" => 256);
isa_ok($val, "Big");
is($val->bit_length, 256);
is(($val % 256)->to_decimal, 1);
ok($val->is_prime);

$val = Big->rand_prime(bits => 256, m => 256);
isa_ok($val, "Big");
is($val->bit_length, 256);
is(($val % 256)->to_decimal, 1);
ok($val->is_prime);

eval { Big->rand_prime(bits => 256, modulus => -256) };
like($@, qr/^Negative modulus at /i);
eval { Big->rand_prime(bits => 256, modulus => 0) };
like($@, qr/^div by zero at /i);
eval { Big->rand_prime(bits => 256, remainder => 8) };
like($@, qr/^Remainder without modulus at /i);

$val = Big->rand_prime(bits => 256, m => 256, remainder => 7);
isa_ok($val, "Big");
is($val->bit_length, 256);
is(($val % 256)->to_decimal, 7);
ok($val->is_prime);

$val = Big->rand_prime(bits => 256, m => 256, r => 7);
isa_ok($val, "Big");
is($val->bit_length, 256);
is(($val % 256)->to_decimal, 7);
ok($val->is_prime);

$val = Big->rand_prime(bits => 256, m => 256, remainder => -7);
isa_ok($val, "Big");
is($val->bit_length, 256);
is(($val % 256)->to_decimal, 256-7);
ok($val->is_prime);

$val = Big->rand_prime(bits => 256, safe => 1);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok((($val -1) / 2)->is_prime);

eval { $val->rand_prime(bits => 256, callback_period => -1) };
like($@, qr/^Negative callback_period at /i);
eval { $val->rand_prime(bits => 256, callback_period => 0) };
like($@, qr/^Zero callback_period at /i);
eval { $val->rand_prime(bits => 256, callback_period => 4) };
like($@, qr/^Callback_period without callback at /i);
eval {
    $val->rand_prime(bits => 256,
                     callback_period => 2,
                     callback => sub { die "foo" });
};
like($@, qr/^foo at /);
$@ = "Vroem";
my (%type, %nr_args);
$val->rand_prime(bits => 256,
                 safe => 1,
                 callback_period => 1,
                 callback => sub { $nr_args{scalar @_}++; $type{$_[0]}++ });
is($@, "");
is_deeply([sort keys %type], [0, 1, 2]);
is_deeply([sort keys %nr_args], [2]);

# Sensitivity propagation
my $len = WEC::SSL::BigInt->new(256);
$len->sensitive(1);
$val = Big->rand_prime(bit_length => $len);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok($val->sensitive);
ok(!$val->tainted);

eval { Big->rand_prime(bit_length => 256, sensitive => $len-$len) };
like($@, qr/^Turning sensitivity off using a sensitive value at /i);

$val = Big->rand_prime(bit_length => $len, sensitive => 0);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok(!$val->sensitive);
ok(!$val->tainted);

$val = Big->rand_prime(bit_length => 256, modulus => $len);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok($val->sensitive);
ok(!$val->tainted);

$val = Big->rand_prime(bit_length => 256, modulus => 257, remainder => $len);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok($val->sensitive);
ok(!$val->tainted);

$val = Big->rand_prime(bit_length => 256,
                       callback_period => $len,
                       callback => sub {});
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok(!$val->sensitive);
ok(!$val->tainted);

# Taint propagation
$val = Big->rand_prime(bit_length => 256 . $taint);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok(!$val->sensitive);
ok($val->tainted);

$val = Big->rand_prime(bit_length => 256, sensitive => $taint);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok(!$val->sensitive);
ok($val->tainted);

$val = Big->rand_prime(bit_length => 256, modulus => 256 . $taint);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok(!$val->sensitive);
ok($val->tainted);

$val = Big->rand_prime(bit_length => 256,
                       modulus => 256,
                       remainder => 1 . $taint);
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok(!$val->sensitive);
ok($val->tainted);

$val = Big->rand_prime(bit_length => 256,
                       callback_period => 1 . $taint,
                       callback => sub {});
isa_ok($val, "Big");
is($val->bit_length, 256);
ok($val->is_prime);
ok(!$val->sensitive);
ok(!$val->tainted);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
