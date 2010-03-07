#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 02_taint.t'
use strict;
use warnings;
use Scalar::Util ();
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Engine
;

{
    package Big;
    our @ISA = qw(WEC::SSL::Engine);
}

my $taint = substr("$0$^W", 0, 0);
my @methods = qw(taint);
can_ok("WEC::SSL::Engine", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$tmp = $result = WEC::SSL::Engine->by_name("dynamic");
ok(!$result->taint);
ok(!$result->taint(1));
ok($result->taint(1));
ok($result->taint);
ok(Scalar::Util::tainted($result));
ok(Scalar::Util::tainted($$result));
ok(!Scalar::Util::tainted($tmp));
ok(Scalar::Util::tainted($$tmp));
ok($result->taint(0));
ok(!$result->taint(0));
ok(!$result->taint);
ok(!Scalar::Util::tainted($result));
ok(!Scalar::Util::tainted($$result));
ok(!Scalar::Util::tainted($tmp));
ok(!Scalar::Util::tainted($$tmp));
$result->taint(28);
ok($result->taint);
$result->taint(undef);
ok(!$result->taint);
$result->taint([]);
ok($result->taint);
$result->taint("0");
ok(!$result->taint);

$tmp = WEC::SSL::Engine->by_name("dynamic");
$tmp->taint(1);
$result->taint($tmp);
ok($result->taint);

$tmp = 0 . $taint;
eval { $result->taint($tmp) };
like($@, qr/^Turning tainting off using a tainted value at /i);
ok($result->taint);

is($result->name, "dynamic");

"WEC::SSL::Engine"->import(@methods);
can_ok(__PACKAGE__, @methods);
