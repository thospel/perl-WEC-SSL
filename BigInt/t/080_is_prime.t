#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 080_is_prime.t'
#########################
our $VERSION = "1.000";

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::BigInt
;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(is_prime);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $val;

for my $in (2, 3, 5, 7, 11, 13, 17, 19,
            "314277828048202396635558256847241559499") {
    $val = Big->new($in);
    ok($val->is_prime);
    ok(WEC::SSL::BigInt::is_prime($in));
}

for my $in (-4, -3, -2, -1, 0, 1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21,
            "314277828048202396635558256847241559497") {
    $val = Big->new($in);
    ok(!$val->is_prime);
    ok(!WEC::SSL::BigInt::is_prime($in));
}

$val = Big->new("314277828048202396635558256847241559499");
eval { $val->is_prime(vroem => 1) };
like($@, qr/^Unknown option 'vroem' at /i);
eval { $val->is_prime("vroem") };
like($@, qr/^Odd number of arguments at /i);
eval { $val->is_prime(checks => 0) };
like($@, qr/^Zero checks at /i);
eval { $val->is_prime(checks => -1) };
like($@, qr/^Negative number of checks at /i);
eval { $val->is_prime(checks => 2**64) };
like($@, qr/^Checks out of range at /i);
eval { $val->is_prime(checks => Big->new(2**64)) };
like($@, qr/^Checks out of range at /i);
ok($val->is_prime(checks => undef));
ok($val->is_prime(checks => 18));
ok($val->is_prime(trial_divisions => 1));
ok($val->is_prime(trial_divisions => 0));
eval { $val->is_prime(callback_period => -1) };
like($@, qr/^Negative callback_period at /i);
eval { $val->is_prime(callback_period => 0) };
like($@, qr/^Zero callback_period at /i);
eval { $val->is_prime(callback_period => 4) };
like($@, qr/^Callback_period without callback at /i);
my @calls;
$@ = "Vroem";
ok($val->is_prime(trial_divisions => 1,
                  checks	  => 8,
                  callback_period => 2,
                  callback => sub { push @calls, [@_] }));
is_deeply(\@calls, [[0, 0], [1, 0], [1, 2], [1, 4], [1, 6]]);
is($@, "");
eval {
    $val->is_prime(trial_divisions => 1,
                   checks	   => 8,
                   callback_period => 2,
                   callback => sub { die "foo" });
};
like($@, qr/^foo at /);

$val = Big->new("314277828048202396635558256847241559497");
ok(!$val->is_prime(checks => 18));
ok(!$val->is_prime(trial_divisions => 1));
ok(!$val->is_prime(trial_divisions => 0));

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
