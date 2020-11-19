#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 002_new.t'
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

my @warns;
$SIG{__WARN__} = sub { push @warns, join("", @_) };

my $result;

# Integer converts
$result = WEC::SSL::BigInt->new(0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(3);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();

$result = Big->new(-3);
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(~0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", ~0);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(1<<31);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 1<<31);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(-(~0>>1)-1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -(~0>>1)-1);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(~0>>1);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", ~0>>1);
ok(!$result->sensitive) if feature_sensitive();

# String converts
$result = WEC::SSL::BigInt->new("+3");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();

my $big = WEC::SSL::BigInt->new("123456789" x 10);
isa_ok($big, "WEC::SSL::BigInt");
is("$big", "123456789" x 10);
ok(!$big->sensitive) if feature_sensitive();

is(@warns, 0);
$result = WEC::SSL::BigInt->new("abc");
is(@warns, 1);
like($warns[0], qr/^Argument "abc" isn.t numeric at/i);
@warns=();
is("$result", 0);
# ok($@ =~ /Decimal contains non-digit/);

is(@warns, 0);
$result = WEC::SSL::BigInt->new("abc123");
is(@warns, 1);
like($warns[0], qr/^Argument "abc123" isn.t numeric at/i);
@warns=();
is("$result", 0);
# ok($@ =~ /Decimal contains non-digit/);

is(@warns, 0);
$result = WEC::SSL::BigInt->new("123abc");
is(@warns, 1);
like($warns[0], qr/^Argument "123abc" isn.t numeric at/i);
@warns=();
is("$result", 123);
# ok($@ =~ /Decimal contains non-digit/);

$result = WEC::SSL::BigInt->new("1e9");
is("$result", "1000000000");
# ok($@ =~ /Decimal contains non-digit/);

# Float converts
$result = WEC::SSL::BigInt->new(0.0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(0.8);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

$result = Big->new(-0.8);
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(3.0);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();

$result = Big->new(-3.0);
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(3.8);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();

$result = Big->new(-3.8);
isa_ok($result, "Big");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(1.2e12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", sprintf("%.0f", 1.2e12));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(-1.2e12);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", sprintf("%.0f", -1.2e12));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(1.2e24);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", sprintf("%.0f", 1.2e24));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(-1.2e24);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", sprintf("%.0f", -1.2e24));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(1.2e24);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", sprintf("%.0f", 1.2e24));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(-1e19);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", sprintf("%.0f", -1e19));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(1e19);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", sprintf("%.0f", 1e19));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new(-1.2e48);
isa_ok($result, "WEC::SSL::BigInt");
is("$result", sprintf("%.0f", -1.2e48));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("1.2e24");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "12" . "0" x 23);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("-1.2e24");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-12" . "0" x 23);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("-1.2e+24");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-12" . "0" x 23);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("-59999e-4");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-5");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("-5999.9e-2");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-59");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("-5999.9e-4");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "0");
ok(!$result->sensitive) if feature_sensitive();

$result = eval { WEC::SSL::BigInt->new("-59999e-" . "4" x 999) };
like($@, qr/^Overflow at /i);

is(@warns, 0);
$result = WEC::SSL::BigInt->new("-59999e");
is(@warns, 1);
like($warns[0], qr/^Argument "-59999e" isn.t numeric at/i);
@warns=();
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "-59999");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("5.9999e2");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "599");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt::add(0, "1e3");
is("$result", "1000");
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("   1234   ");
isa_ok($result, "WEC::SSL::BigInt");
is("$result", "1234");
ok(!$result->sensitive) if feature_sensitive();

is(@warns, 0);
$result = WEC::SSL::BigInt->new("");
is(@warns, 1);
like($warns[0], qr/^Argument "" isn.t numeric at/i);
@warns=();
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

is(@warns, 0);
$result = WEC::SSL::BigInt->new("   ");
is(@warns, 1);
like($warns[0], qr/^Argument "   " isn.t numeric at/i);
@warns=();
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

is(@warns, 0);
$result = WEC::SSL::BigInt->new(".");
is(@warns, 1);
like($warns[0], qr/^Argument "." isn.t numeric at/i);
@warns=();
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

my $a = 1.2e48;		# Set up NOK
my $b = $a . "zzzz";	# Also cause POK
$result = WEC::SSL::BigInt->new($a);
is("$result", "12" . "0" x 47);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("   1234");
is("$result", 1234);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt->new("   -1234");
is("$result", -1234);
ok(!$result->sensitive) if feature_sensitive();

my $copy = WEC::SSL::BigInt->new($result);
is("$copy",   -1234, "Copy has same value as original");
ok(!$result->sensitive) if feature_sensitive();
ok(!$copy->sensitive) if feature_sensitive();
$result->abs_bit(0, 1);
is("$result", -1235, "Succesfully changed original");
is("$copy",   -1234, "Changing original does not change copy");

SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    $result->sensitive(1);
    ok($result->sensitive);
    $copy = WEC::SSL::BigInt->new($result);
    is("$copy",   -1235, "Copy has same value as original");
    ok($result->sensitive);
    ok($copy->sensitive);
    $result->abs_bit(0, 0);
    is("$result", -1234, "Succesfully changed original");
    is("$copy",   -1235, "Changing original does not change copy");
}

my $taint = substr("$0$^X", 0, 0);
my $arg = "1234" . $taint;
$result = WEC::SSL::BigInt->new($arg);
ok(tainted($result));
my $r = "$result";
ok(tainted($r));

SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    $result->taint(0);
    ok(!tainted($result));
    $r = "$result";
    ok(!tainted($r));

    $result->taint(1);
    ok(tainted($result));
    $r = "$result";
    ok(tainted($r));

    $result->taint(0);
    ok(!tainted($result));

    $result->taint(1);
    ok(tainted($result));
    $r = "$result";
    ok(tainted($r));

    my $tmp = WEC::SSL::BigInt->new($result);
    ok(tainted($tmp));
    $r = "$tmp";
    ok(tainted($r));
    is($r, 1234);

    eval { $result->taint($taint) };
    like($@, qr/Turning tainting off using a tainted value/i);
}

# Using add to force perl_int conversions
$result = WEC::SSL::BigInt::add(0, 3.0);
is("$result", 3);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt::add(0, -3.0);
is("$result", -3);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt::add(0, ~0);
is("$result", ~0);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt::add(0, ~0 >> 1);
is("$result", ~0 >> 1);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt::add(0, -(~0 >> 1)-1);
is("$result", -(~0 >> 1)-1);
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt::add(0, 1.2e48);
is("$result", sprintf("%.0f", 1.2e48));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt::add(0, -1.2e48);
is("$result", sprintf("%.0f", -1.2e48));
ok(!$result->sensitive) if feature_sensitive();

$result = WEC::SSL::BigInt::perl_int(WEC::SSL::BigInt->new(1.2e48));
is($result, 1.2e48);
is(ref($result), "");

$result = eval { WEC::SSL::BigInt::to_integer(WEC::SSL::BigInt->new(1.2e48)) };
like($@, qr/value out of range/);

$result = WEC::SSL::BigInt::to_integer(WEC::SSL::BigInt->new(~0));
is($result, ~0);
is(ref($result), "");

$result = eval { WEC::SSL::BigInt::to_integer(WEC::SSL::BigInt->new(~0+1)) };
like($@, qr/value out of range/);

$result = WEC::SSL::BigInt::to_integer(WEC::SSL::BigInt->new(-(~0 >> 1))-1);
is($result, -(~0 >> 1)-1);
is(ref($result), "");

$result = eval { WEC::SSL::BigInt::to_integer(WEC::SSL::BigInt->new(-(~0 >> 1)-2)) };
like($@, qr/value out of range/);

$result = eval { WEC::SSL::BigInt::abs_to_integer(WEC::SSL::BigInt->new(1.2e48)) };
like($@, qr/value out of range/);

$result = WEC::SSL::BigInt::abs_to_integer(WEC::SSL::BigInt->new(~0));
is($result, ~0);
is(ref($result), "");

$result = eval { WEC::SSL::BigInt::abs_to_integer(WEC::SSL::BigInt->new(~0+1)) };
like($@, qr/value out of range/);

$result = WEC::SSL::BigInt::abs_to_integer(WEC::SSL::BigInt->new(-~0));
is($result, ~0);
is(ref($result), "");

$result = eval { WEC::SSL::BigInt::to_integer(WEC::SSL::BigInt->new(-~0-1)) };
like($@, qr/value out of range/);

my $inf = 9**9**9;
if ($inf/2 == $inf) {
    # We really support infinity
    $result = eval { WEC::SSL::BigInt->new($inf) };
    like($@, qr/Cannot convert infinity to an integer at/i);
    $result = eval { WEC::SSL::BigInt->new(-$inf) };
    like($@, qr/Cannot convert infinity to an integer at/i);

    $result = eval { WEC::SSL::BigInt->new(0) + $inf};
    like($@, qr/Cannot convert infinity to an integer at/i);
    $result = eval { WEC::SSL::BigInt->new(0) + -$inf};
    like($@, qr/Cannot convert infinity to an integer at/i);

    my $nan = $inf / $inf;
    if ($nan != $nan) {
        # We really support NaN
        $result = eval { WEC::SSL::BigInt->new($nan) };
        like($@, qr/Cannot convert NaN to an integer at/i);

        $result = eval { WEC::SSL::BigInt->new(0) + $nan };
        like($@, qr/Cannot convert NaN to an integer at/i);
    }
}

# As string we always support infinity
$result = eval { WEC::SSL::BigInt->new("inf") };
like($@, qr/Cannot convert infinity to an integer at/i);
$result = eval { WEC::SSL::BigInt->new("  -INFORMATION  ") };
like($@, qr/Cannot convert infinity to an integer at/i);

$result = eval { WEC::SSL::BigInt->new(0) + "inf"};
like($@, qr/Cannot convert infinity to an integer at/i);
$result = eval { WEC::SSL::BigInt->new(0) + "  -INFORMATION  "};
like($@, qr/Cannot convert infinity to an integer at/i);

# We string we always support NaN
$result = eval { WEC::SSL::BigInt->new("nan") };
like($@, qr/Cannot convert NaN to an integer at/i);
$result = eval { WEC::SSL::BigInt->new("  -NANOMETER  ") };
like($@, qr/Cannot convert NaN to an integer at/i);

$result = eval { WEC::SSL::BigInt->new(0) + "nan" };
like($@, qr/Cannot convert NaN to an integer at/i);
$result = eval { WEC::SSL::BigInt->new(0) + "  -NANOMETER  " };
like($@, qr/Cannot convert NaN to an integer at/i);

# Undef should give 0
is(@warns, 0);
$result = WEC::SSL::BigInt->new(undef);
is(@warns, 1);
like($warns[0], qr/^Use of uninitialized value in subroutine entry at /i);
@warns=();
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

is(@warns, 0);
$result = WEC::SSL::BigInt->new(0) + undef;
is(@warns, 1);
like($warns[0], qr/^Use of uninitialized value in null operation at /i);
@warns=();
is("$result", 0);
ok(!$result->sensitive) if feature_sensitive();

my $tmp = Big->new(-28);
$result = WEC::SSL::BigInt->new($tmp);
is(ref($result), "WEC::SSL::BigInt");
is("$result", -28);
ok(!$result->sensitive) if feature_sensitive();
ok(!$result->taint) if feature_taint();

SKIP: {
    skip "Compiled without sensitive support" if !feature_sensitive();

    my $tmp = Big->new(-28);
    $tmp->sensitive(1);
    $result = WEC::SSL::BigInt->new($tmp);
    is(ref($result), "WEC::SSL::BigInt");
    is("$result", -28);
    ok($result->sensitive);
    ok(!$result->taint) if feature_taint();

    $tmp->sensitive(0);
    $result = WEC::SSL::BigInt->new($tmp);
    is(ref($result), "WEC::SSL::BigInt");
    is("$result", -28);
    ok(!$result->sensitive);
    ok(!$result->taint) if feature_taint();
}

SKIP: {
    skip "Compiled without taint support" if !feature_taint();

    my $tmp = Big->new(-28);
    $tmp->taint(1);
    $result = WEC::SSL::BigInt->new($tmp);
    is(ref($result), "WEC::SSL::BigInt");
    is("$result", -28);
    ok(!$result->sensitive) if feature_sensitive();
    ok($result->taint);

    $tmp->taint(0);
    $result = Big->new($tmp);
    is(ref($result), "Big");
    is("$result", -28);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$result->taint);
}

is(@warns, 0);
diag($_) for @warns;
