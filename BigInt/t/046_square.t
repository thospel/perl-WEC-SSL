#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 046_square.t'

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

my @methods = qw(square);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($arg, $tmp, $result);



















# square(-3) = 9
$arg = Big->new(-3);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -3);

$result = WEC::SSL::BigInt::square(-3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!tainted($result));


# square(-2) = 4
$arg = Big->new(-2);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -2);

$result = WEC::SSL::BigInt::square(-2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!tainted($result));


# square(-1) = 1
$arg = Big->new(-1);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -1);

$result = WEC::SSL::BigInt::square(-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));


# square(0) = 0
$arg = Big->new(0);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 0);

$result = WEC::SSL::BigInt::square(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!tainted($result));


# square(1) = 1
$arg = Big->new(1);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 1);

$result = WEC::SSL::BigInt::square(1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1);
ok(!tainted($result));


# square(2) = 4
$arg = Big->new(2);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 2);

$result = WEC::SSL::BigInt::square(2);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 4);
ok(!tainted($result));


# square(3) = 9
$arg = Big->new(3);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 3);

$result = WEC::SSL::BigInt::square(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 9);
ok(!tainted($result));


# square(9) = 81
$arg = Big->new(9);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 9);

$result = WEC::SSL::BigInt::square(9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!tainted($result));


# square(-9) = 81
$arg = Big->new(-9);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -9);

$result = WEC::SSL::BigInt::square(-9);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 81);
ok(!tainted($result));


# square(12) = 144
$arg = Big->new(12);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 12);

$result = WEC::SSL::BigInt::square(12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!tainted($result));


# square(-12) = 144
$arg = Big->new(-12);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -12);

$result = WEC::SSL::BigInt::square(-12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 144);
ok(!tainted($result));


# square(581) = 337561
$arg = Big->new(581);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", 581);

$result = WEC::SSL::BigInt::square(581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!tainted($result));


# square(-581) = 337561
$arg = Big->new(-581);

$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
$result = WEC::SSL::BigInt::square($arg, undef, 1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
$tmp = $arg->copy;
$result = WEC::SSL::BigInt::square($tmp, undef, undef);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
isa_ok($tmp, "WEC::SSL::BigInt");
is("$arg", -581);

$result = WEC::SSL::BigInt::square(-581);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
$result = $arg->square;
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);
ok(!tainted($result));
# Check sensitive propagation
$arg->sensitive(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok($result->sensitive);

$arg->sensitive(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!$result->sensitive);

# Check taint propagation
$arg->tainted(1);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(tainted($result));

$arg->tainted(0);
$result = WEC::SSL::BigInt::square($arg);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 337561);
ok(!tainted($result));



"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);