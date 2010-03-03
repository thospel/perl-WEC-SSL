#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 014_modulo.t'

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

my @methods = qw(modulo);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg1, $arg2, $tmp, $result);

# modulo(-1, -1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::modulo(-1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(-1, 0) fails
$arg1 = Big->new(-1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::modulo($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::modulo($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", -1);

$result = eval { WEC::SSL::BigInt::modulo(-1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->modulo($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->modulo(0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1 % $arg2 };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1 % 0 };
like($@, qr/\Qdiv by zero/i);

$result = eval { -1 % $arg2 };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= 0 };
like($@, qr/\Qdiv by zero/i);
is("$arg1", -1);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!tainted($tmp));

# modulo(-1, 1) = 0
$arg1 = Big->new(-1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -1);

$result = WEC::SSL::BigInt::modulo(-1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(0, -1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::modulo(0, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 0 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(0, 0) fails
$arg1 = Big->new(0);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::modulo($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::modulo($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 0);

$result = eval { WEC::SSL::BigInt::modulo(0, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->modulo($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->modulo(0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1 % $arg2 };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1 % 0 };
like($@, qr/\Qdiv by zero/i);

$result = eval { 0 % $arg2 };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= 0 };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 0);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!tainted($tmp));

# modulo(0, 1) = 0
$arg1 = Big->new(0);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 0);

$result = WEC::SSL::BigInt::modulo(0, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 0 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 0);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(1, -1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(-1);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::modulo(1, -1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= -1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(1, 0) fails
$arg1 = Big->new(1);
$arg2 = Big->new(0);

$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { WEC::SSL::BigInt::modulo($arg2, $arg1, 1) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1->copy;
$result = eval { WEC::SSL::BigInt::modulo($tmp, $arg2, undef) };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 1);

$result = eval { WEC::SSL::BigInt::modulo(1, 0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->modulo($arg2) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1->modulo(0) };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1 % $arg2 };
like($@, qr/\Qdiv by zero/i);

$result = eval { $arg1 % 0 };
like($@, qr/\Qdiv by zero/i);

$result = eval { 1 % $arg2 };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= 0 };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 1);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!$tmp->sensitive);
$arg2->sensitive(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(tainted($tmp));
$arg2->tainted(1);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(tainted($tmp));
$arg1->tainted(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!tainted($tmp));
$arg2->tainted(0);
$result = eval { WEC::SSL::BigInt::modulo($arg1, $arg2) };
like($@, qr/\Qdiv by zero/i);

$tmp = $arg1;
eval { $tmp %= $arg2 };
like($@, qr/\Qdiv by zero/i);
ok(!tainted($tmp));

# modulo(1, 1) = 0
$arg1 = Big->new(1);
$arg2 = Big->new(1);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 1);

$result = WEC::SSL::BigInt::modulo(1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= 1;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 0);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 1);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(12, 9) = 3
$arg1 = Big->new(12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::modulo(12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 12 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 3);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 3);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(-12, 9) = 6
$arg1 = Big->new(-12);
$arg2 = Big->new(9);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::modulo(-12, 9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -12 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= 9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 6);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 6);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 6);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(12, -9) = -6
$arg1 = Big->new(12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 12);

$result = WEC::SSL::BigInt::modulo(12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 12 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -6);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -6);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -6);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(-12, -9) = -3
$arg1 = Big->new(-12);
$arg2 = Big->new(-9);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -12);

$result = WEC::SSL::BigInt::modulo(-12, -9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -12 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= -9;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -3);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -3);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -12);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(581, 3) = 2
$arg1 = Big->new(581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::modulo(581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 581 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 2);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 2);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 2);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(581, -3) = -1
$arg1 = Big->new(581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", 581);

$result = WEC::SSL::BigInt::modulo(581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = 581 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", 581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -1);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(-581, 3) = 1
$arg1 = Big->new(-581);
$arg2 = Big->new(3);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::modulo(-581, 3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -581 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= 3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", 1);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));

# modulo(-581, -3) = -2
$arg1 = Big->new(-581);
$arg2 = Big->new(-3);

$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::modulo($arg2, $arg1, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1->copy;
$result = WEC::SSL::BigInt::modulo($tmp, $arg2, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg1", -581);

$result = WEC::SSL::BigInt::modulo(-581, -3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo($arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1->modulo(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg1 % -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$result = -581 % $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg1;
$tmp %= -3;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -2);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);

$tmp = $arg1;
$tmp %= $arg2;
isa_ok($result, "WEC::SSL::BigInt");
is("$tmp", -2);
ok(!$tmp->sensitive);
ok(!tainted($tmp));
is("$arg1", -581);
# Check sensitive propagation
$arg1->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg1->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok($result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok($tmp->sensitive);
$arg2->sensitive(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!$result->sensitive);

$tmp = $arg1;
$tmp %= $arg2;
ok(!$tmp->sensitive);
# Check taint propagation
$arg1->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(1);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg1->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(tainted($tmp));
$arg2->tainted(0);
$result = WEC::SSL::BigInt::modulo($arg1, $arg2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -2);
ok(!tainted($result));

$tmp = $arg1;
$tmp %= $arg2;
ok(!tainted($tmp));
















"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);