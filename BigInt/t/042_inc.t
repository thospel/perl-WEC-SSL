#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 042_inc.t'
#########################
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

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(inc inc_mutate);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

for (-28, -2, -1, 0, 1, 2, 28) {
    # post ++
    $result = Big->new($_);
    $tmp = $result++;
    is("$tmp", $_);
    is("$result", $_+1);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->taint) if feature_taint();
    is(ref($result), "WEC::SSL::BigInt");
    is(ref($tmp), "Big");

    # pre ++
    $result = Big->new($_);
    $tmp = ++$result;
    is("$tmp", $_+1);
    is("$result", $_+1);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->taint) if feature_taint();
    is(ref($result), "Big");
    is(ref($tmp), "Big");

    # inc_mutate
    $result = Big->new($_);
    $tmp = $result->inc_mutate;
    is("$tmp", $_+1);
    is("$result", $_+1);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->taint) if feature_taint();
    is(ref($result), "Big");
    is(ref($tmp), "Big");

    # inc_mutate on perl vars
    $result = $_;
    $tmp = WEC::SSL::BigInt::inc_mutate($result);
    is("$tmp", $_+1);
    is("$result", $_+1);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$tmp->taint) if feature_taint();
    is(ref($result), "WEC::SSL::BigInt");
    is(ref($tmp), "WEC::SSL::BigInt");

    # inc
    $result = Big->new($_);
    $tmp = $result->inc;
    is("$tmp", $_+1);
    is("$result", $_);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->taint) if feature_taint();
    is(ref($result), "Big");
    is(ref($tmp), "WEC::SSL::BigInt");

    # inc on perl vars
    $result = $_;
    $tmp = WEC::SSL::BigInt::inc($result);
    is("$tmp", $_+1);
    is($result, $_);
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$tmp->taint) if feature_taint();
    is(ref($result), "");
    is(ref($tmp), "WEC::SSL::BigInt");

    # inc inplace
    $result = Big->new($_);
    $tmp = $result->inc(undef, undef);
    is("$tmp", $_+1);
    is("$result", $_+1);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->taint) if feature_taint();
    is(ref($result), "Big");
    is(ref($tmp), "Big");

    # inc inplace on perl vars
    $result = $_;
    $tmp = WEC::SSL::BigInt::inc($result, undef, undef);
    is("$tmp", $_+1);
    is("$result", $_+1);
    ok(!$result->sensitive) if feature_sensitive();
    ok(!$result->taint) if feature_taint();
    ok(!$tmp->sensitive) if feature_sensitive();
    ok(!$tmp->taint) if feature_taint();
    is(ref($result), "WEC::SSL::BigInt");
    is(ref($tmp), "WEC::SSL::BigInt");

  SKIP: {
      skip "Compiled without sensitive support" if !feature_sensitive();

      $result = Big->new($_);
      $result->sensitive(1);
      $tmp = $result++;
      is("$tmp", $_);
      is("$result", $_+1);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok(!$result->taint) if feature_taint();
      ok(!$tmp->taint) if feature_taint();
      is(ref($result), "WEC::SSL::BigInt");
      is(ref($tmp), "Big");

      $result = Big->new($_);
      $result->sensitive(1);
      $tmp = ++$result;
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok(!$result->taint) if feature_taint();
      ok(!$tmp->taint) if feature_taint();
      is(ref($result), "Big");
      is(ref($tmp), "Big");

      $result = Big->new($_);
      $result->sensitive(1);
      $tmp = $result->inc_mutate;
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok(!$result->taint) if feature_taint();
      ok(!$tmp->taint) if feature_taint();
      is(ref($result), "Big");
      is(ref($tmp), "Big");

      $result = Big->new($_);
      $result->sensitive(1);
      $tmp = $result->inc;
      is("$tmp", $_+1);
      is("$result", $_);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok(!$result->taint) if feature_taint();
      ok(!$tmp->taint) if feature_taint();
      is(ref($result), "Big");
      is(ref($tmp), "WEC::SSL::BigInt");

      $result = Big->new($_);
      $result->sensitive(1);
      $tmp = $result->inc(undef, undef);
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok(!$result->taint) if feature_taint();
      ok(!$tmp->taint) if feature_taint();
      is(ref($result), "Big");
      is(ref($tmp), "Big");
    }

  SKIP: {
      skip "Compiled without taint support" if !feature_taint();

      $result = Big->new($_);
      $result->taint(1);
      $tmp = $result++;
      is("$tmp", $_);
      is("$result", $_+1);
      ok(!$result->sensitive) if feature_sensitive();
      ok(!$tmp->sensitive) if feature_sensitive();
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "WEC::SSL::BigInt");
      is(ref($tmp), "Big");

      $result = Big->new($_);
      $result->taint(1);
      $tmp = ++$result;
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok(!$result->sensitive) if feature_sensitive();
      ok(!$tmp->sensitive) if feature_sensitive();
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "Big");
      is(ref($tmp), "Big");

      $result = Big->new($_);
      $result->taint(1);
      $tmp = $result->inc_mutate;
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok(!$result->sensitive) if feature_sensitive();
      ok(!$tmp->sensitive) if feature_sensitive();
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "Big");
      is(ref($tmp), "Big");

      $result = $_ . $taint;;
      $tmp = WEC::SSL::BigInt::inc_mutate($result);
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok(!$result->sensitive) if feature_sensitive();
      ok($result->taint);
      ok(!$tmp->sensitive) if feature_sensitive();
      ok($tmp->taint);
      is(ref($result), "WEC::SSL::BigInt");
      is(ref($tmp), "WEC::SSL::BigInt");

      $result = Big->new($_);
      $result->taint(1);
      $tmp = $result->inc;
      is("$tmp", $_+1);
      is("$result", $_);
      ok(!$result->sensitive) if feature_sensitive();
      ok(!$tmp->sensitive) if feature_sensitive();
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "Big");
      is(ref($tmp), "WEC::SSL::BigInt");

      $result = $_ . $taint;;
      $tmp = WEC::SSL::BigInt::inc($result);
      is("$tmp", $_+1);
      is($result, $_);
      ok(!$tmp->sensitive) if feature_sensitive();
      ok($tmp->taint);
      is(ref($result), "");
      is(ref($tmp), "WEC::SSL::BigInt");

      $result = Big->new($_);
      $result->taint(1);
      $tmp = $result->inc(undef, undef);
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok(!$result->sensitive) if feature_sensitive();
      ok(!$tmp->sensitive) if feature_sensitive();
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "Big");
      is(ref($tmp), "Big");

      $result = $_ . $taint;;
      $tmp = WEC::SSL::BigInt::inc($result, undef, undef);
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok(!$result->sensitive) if feature_sensitive();
      ok($result->taint);
      ok(!$tmp->sensitive) if feature_sensitive();
      ok($tmp->taint);
      is(ref($result), "WEC::SSL::BigInt");
      is(ref($tmp), "WEC::SSL::BigInt");
    }

  SKIP: {
      skip "Compiled without sensitive support" if !feature_sensitive();
      skip "Compiled without taint support" if !feature_taint();

      $result = Big->new($_);
      $result->taint(1);
      $result->sensitive(1);
      $tmp = $result++;
      is("$tmp", $_);
      is("$result", $_+1);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "WEC::SSL::BigInt");
      is(ref($tmp), "Big");

      $result = Big->new($_);
      $result->taint(1);
      $result->sensitive(1);
      $tmp = ++$result;
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "Big");
      is(ref($tmp), "Big");

      $result = Big->new($_);
      $result->taint(1);
      $result->sensitive(1);
      $tmp = $result->inc_mutate;
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "Big");
      is(ref($tmp), "Big");

      $result = Big->new($_);
      $result->taint(1);
      $result->sensitive(1);
      $tmp = $result->inc;
      is("$tmp", $_+1);
      is("$result", $_);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "Big");
      is(ref($tmp), "WEC::SSL::BigInt");

      $result = Big->new($_);
      $result->taint(1);
      $result->sensitive(1);
      $tmp = $result->inc(undef, undef);
      is("$tmp", $_+1);
      is("$result", $_+1);
      ok($result->sensitive);
      ok($tmp->sensitive);
      ok($result->taint);
      ok($tmp->taint);
      is(ref($result), "Big");
      is(ref($tmp), "Big");
    }
}

my $copy;
$copy = $result = Big->new(28);
$tmp = $result++;
is("$tmp", 28);
is("$copy", 28);
is("$result", 29);
ok(!$result->sensitive) if feature_sensitive();
ok(!$tmp->sensitive) if feature_sensitive();
ok(!$result->taint) if feature_taint();
ok(!$tmp->taint) if feature_taint();
is(ref($result), "WEC::SSL::BigInt");
is(ref($tmp), "Big");
is(ref($copy), "Big");

$copy = $result = Big->new(28);
$tmp = ++$result;
is("$tmp", 29);
is("$copy", 28);
is("$result", 29);
ok(!$result->sensitive) if feature_sensitive();
ok(!$tmp->sensitive) if feature_sensitive();
ok(!$result->taint) if feature_taint();
ok(!$tmp->taint) if feature_taint();
is(ref($result), "WEC::SSL::BigInt");
is(ref($tmp), "WEC::SSL::BigInt");
is(ref($copy), "Big");

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
