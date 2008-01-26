#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 015_pow.t'

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok("WEC::SSL::BigInt") };

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw(pow);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# pow(-1, -1) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { WEC::SSL::BigInt::pow($arg2, $arg1, 1) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::pow($tmp, $arg2, undef) };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -1);

$result = eval { WEC::SSL::BigInt::pow(-1, -1) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow($arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow(-1) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** -1 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { (-1) ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= -1 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -1);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));

# pow(-1, 0) = 1
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::pow(-1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = (-1) ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(-1, 1) = -1
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::pow(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = (-1) ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(0, -1) fails
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { WEC::SSL::BigInt::pow($arg2, $arg1, 1) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::pow($tmp, $arg2, undef) };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 0);

$result = eval { WEC::SSL::BigInt::pow(0, -1) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow($arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow(-1) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** -1 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { 0 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= -1 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 0);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));

# pow(0, 0) = 1
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::pow(0, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 0 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::pow(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 0 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(1, -1) fails
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { WEC::SSL::BigInt::pow($arg2, $arg1, 1) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::pow($tmp, $arg2, undef) };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 1);

$result = eval { WEC::SSL::BigInt::pow(1, -1) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow($arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow(-1) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** -1 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { 1 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= -1 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 1);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));

# pow(1, 0) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::pow(1, 0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 0;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(1, 1) = 1
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::pow(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(12, 9) = 5159780352
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::pow(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = 12 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", "5159780352");
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", "5159780352");
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "5159780352");
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(-12, 9) = -5159780352
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::pow(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$result = (-12) ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", "-5159780352");
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", "-5159780352");
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5159780352");
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(12, -9) fails
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { WEC::SSL::BigInt::pow($arg2, $arg1, 1) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::pow($tmp, $arg2, undef) };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 12);

$result = eval { WEC::SSL::BigInt::pow(12, -9) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow($arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow(-9) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** -9 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { 12 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= -9 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 12);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));

# pow(-12, -9) fails
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { WEC::SSL::BigInt::pow($arg2, $arg1, 1) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::pow($tmp, $arg2, undef) };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -12);

$result = eval { WEC::SSL::BigInt::pow(-12, -9) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow($arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow(-9) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** -9 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { (-12) ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= -9 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -12);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));

# pow(581, 3) = 196122941
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::pow(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 581 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 196122941);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 196122941);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 196122941);
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(581, -3) fails
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { WEC::SSL::BigInt::pow($arg2, $arg1, 1) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::pow($tmp, $arg2, undef) };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 581);

$result = eval { WEC::SSL::BigInt::pow(581, -3) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow($arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow(-3) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** -3 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { 581 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= -3 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 581);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", 581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));

# pow(-581, 3) = -196122941
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::pow($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::pow($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::pow(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->pow(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 ** 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$result = (-581) ** $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp **= 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -196122941);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);

$tmp = $arg1;
$tmp **= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -196122941);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok($result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp **= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::pow($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -196122941);
ok(!tainted($result));

$tmp = $arg1;
$tmp **= $arg2;
ok(!tainted($tmp));

# pow(-581, -3) fails
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { WEC::SSL::BigInt::pow($arg2, $arg1, 1) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::pow($tmp, $arg2, undef) };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -581);

$result = eval { WEC::SSL::BigInt::pow(-581, -3) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow($arg2) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1->pow(-3) };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { $arg1 ** -3 };
like($@, qr/\QNegative exponent not supported/i);

$result = eval { (-581) ** $arg2 };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= -3 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -581);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
is("$arg1", -581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::pow($arg1, $arg2) };
like($@, qr/\QNegative exponent not supported/i);

$tmp = $arg1;
eval { $tmp **= $arg2 };
like($@, qr/\QNegative exponent not supported/i);
ok(!tainted($tmp));
















"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
