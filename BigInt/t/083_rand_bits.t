#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 083_rand_bits.t'
#########################
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL qw(feature_sensitive feature_taint);
    use WEC::SSL::BigInt;
    use WEC::SSL::Rand;
;

# Fake seeding the PRNG
WEC::SSL::Rand::seed("1" x 1024);

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(rand_bits);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($val, $result);

$result = Big->rand_bits(bit_length => 0);
is("$result", 0);
isa_ok($result, "Big");
ok(!$result->sensitive) if feature_sensitive();
ok(!$result->taint);

$result = eval { Big->rand_bits(bit_length => -1) };
like($@, qr/^Negative number of bits at /i);

$result = eval { Big->rand_bits(bits => -1) };
like($@, qr/^Negative number of bits at /i);

$result = eval { Big->rand_bits(floepr => 28) };
like($@, qr/^Unknown option 'floepr' at /i);

$result = eval { Big->rand_bits("floepr") };
like($@, qr/^Odd number of arguments at /i);

$result = eval { Big->rand_bits };
like($@, qr/^No bits argument at /i);

$result = eval { Big->rand_bits(bit_length => 5, lsb_ones => -1) };
like($@, qr/^Negative number of lsb_ones at /i);

$result = eval { Big->rand_bits(bit_length => 5, lsb_ones => 2) };
like($@, qr/^More than 1 lsb_ones is unsupported at /i);

$result = eval { Big->rand_bits(bit_length => 5, msb_ones => -1) };
like($@, qr/^Negative number of msb_ones at /i);

$result = eval { Big->rand_bits(bit_length => 5, msb_ones => 3) };
like($@, qr/^More than 2 msb_ones is unsupported at /i);

$result = eval { Big->rand_bits(bit_length => 0, lsb_ones => 1) };
like($@, qr/^More lsb_ones than bits at /i);

$result = eval { Big->rand_bits(bit_length => 1, msb_ones => 2) };
like($@, qr/^More msb_ones than bits at /i);

for (0..5) {
    $result = Big->rand_bits(bit_length => 1, lsb_ones => 1);
    is("$result", 1);

    $result = Big->rand_bits(bit_length => 1, msb_ones => 1);
    is("$result", 1);

    $result = Big->rand_bits(bit_length => 2, msb_ones => 2);
    is("$result", 3);

    $result = Big->rand_bits(bit_length => 1, msb_ones => 1, lsb_ones => 1);
    is("$result", 1);

    $result = Big->rand_bits(bit_length => 2, msb_ones => 1, lsb_ones => 1);
    is("$result", 3);

    $result = Big->rand_bits(bit_length => 2, msb_ones => 2, lsb_ones => 1);
    is("$result", 3);

    $result = Big->rand_bits(bit_length => 3, msb_ones => 2, lsb_ones => 1);
    is("$result", 7);
}

my %results;
$results{Big->rand_bits(bit_length => 2)}++ for 1..1000;
# Check reasonable spread (extremely small chance of random failure)
is_deeply([sort {$a <=> $b } keys %results], [0..3]);
for (0..3) {
    ok($results{$_} > 1000/4/2);
}

%results = ();
$results{Big->rand_bits(bit_length => 2, lsb_ones => 0)}++ for 1..1000;
# Check reasonable spread (extremely small chance of random failure)
is_deeply([sort {$a <=> $b } keys %results], [0..3]);
for (0..3) {
    ok($results{$_} > 1000/4/2);
}

%results = ();
$results{Big->rand_bits(bit_length => 2, lsb_ones => 1)}++ for 1..1000;
# Check reasonable spread (extremely small chance of random failure)
is_deeply([sort {$a <=> $b } keys %results], [1, 3]);
for (1, 3) {
    ok($results{$_} > 1000/2/2);
}

%results = ();
$results{Big->rand_bits(bit_length => 2, msb_ones => 0)}++ for 1..1000;
# Check reasonable spread (extremely small chance of random failure)
is_deeply([sort {$a <=> $b } keys %results], [0..3]);
for (0..3) {
    ok($results{$_} > 1000/4/2);
}

%results = ();
$results{Big->rand_bits(bit_length => 2, msb_ones => 1)}++ for 1..1000;
# Check reasonable spread (extremely small chance of random failure)
is_deeply([sort {$a <=> $b } keys %results], [2, 3]);
for (2, 3) {
    ok($results{$_} > 1000/2/2);
}

%results = ();
$results{Big->rand_bits(bit_length => 3, msb_ones => 2)}++ for 1..1000;
# Check reasonable spread (extremely small chance of random failure)
is_deeply([sort {$a <=> $b } keys %results], [6, 7]);
for (6, 7) {
    ok($results{$_} > 1000/2/2);
}

# Sensitivity
SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $result = Big->rand_bits(bit_length => 5, sensitive => 1);
    ok($result < 2**5);
    ok($result->sensitive);
    ok(!$result->taint) if feature_taint();

    $val = Big->new(5);
    $val->sensitive(1);
    $result = Big->rand_bits(bit_length => $val);
    ok($result < 2**$val);
    ok($result->sensitive);
    ok(!$result->taint) if feature_taint();

    $val = Big->new(1);
    $val->sensitive(1);
    $result = Big->rand_bits(bit_length => 5, lsb_ones => $val);
    ok($result < 2**5);
    ok($result->sensitive);
    ok(!$result->taint) if feature_taint();

    $val = Big->new(1);
    $val->sensitive(1);
    $result = Big->rand_bits(bit_length => 5, msb_ones => $val);
    ok($result < 2**5);
    ok($result->sensitive);
    ok(!$result->taint) if feature_taint();

    $val = Big->new(1);
    $val->sensitive(1);
    $result = Big->rand_bits(bit_length => 5, msb_ones => $val, sensitive => 0);
    ok($result < 2**5);
    ok(!$result->sensitive);
    ok(!$result->taint) if feature_taint();

    $val = Big->new(1);
    $val->sensitive(1);
    $result = Big->rand_bits(bit_length => 5, sensitive => $val);
    ok($result < 2**5);
    ok($result->sensitive);
    ok(!$result->taint) if feature_taint();

    $val = Big->new(0);
    $val->sensitive(1);
    $result = eval { Big->rand_bits(bit_length => 5, sensitive => $val) };
    like($@, qr/^Turning sensitivity off using a sensitive value at /);
}

# Tainted
SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $val = Big->new(5);
    $val->taint(1);
    $result = Big->rand_bits(bit_length => $val);
    ok($result < 2**$val);
    ok(!$result->sensitive) if feature_sensitive();
    ok($result->taint);

    $val = Big->new(1);
    $val->taint(1);
    $result = Big->rand_bits(bit_length => 5, lsb_ones => $val);
    ok($result < 2**5);
    ok(!$result->sensitive) if feature_sensitive();
    ok($result->taint);

    $val = Big->new(1);
    $val->taint(1);
    $result = Big->rand_bits(bit_length => 5, msb_ones => $val);
    ok($result < 2**5);
    ok(!$result->sensitive) if feature_sensitive();
    ok($result->taint);
}

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
