#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 02_tainted.t'

use strict;
use warnings;
use Scalar::Util ();
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok("WEC::SSL::Engine") };

{
    package Big;
    our @ISA = qw(WEC::SSL::Engine);
}

my $taint = substr("$0$^W", 0, 0);
my @methods = qw(tainted);
can_ok("WEC::SSL::Engine", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$tmp = $result = WEC::SSL::Engine->by_name("dynamic");
ok(!$result->tainted);
ok(!$result->tainted(1));
ok($result->tainted(1));
ok($result->tainted);
ok(Scalar::Util::tainted($result));
ok(Scalar::Util::tainted($$result));
ok(!Scalar::Util::tainted($tmp));
ok(Scalar::Util::tainted($$tmp));
ok($result->tainted(0));
ok(!$result->tainted(0));
ok(!$result->tainted);
ok(!Scalar::Util::tainted($result));
ok(!Scalar::Util::tainted($$result));
ok(!Scalar::Util::tainted($tmp));
ok(!Scalar::Util::tainted($$tmp));
$result->tainted(28);
ok($result->tainted);
$result->tainted(undef);
ok(!$result->tainted);
$result->tainted([]);
ok($result->tainted);
$result->tainted("0");
ok(!$result->tainted);

$tmp = WEC::SSL::Engine->by_name("dynamic");
$tmp->tainted(1);
$result->tainted($tmp);
ok($result->tainted);

$tmp = 0 . $taint;
eval { $result->tainted($tmp) };
like($@, qr/^Turning tainting off using a tainted value at /i);
ok($result->tainted);

is($result->name, "dynamic");

"WEC::SSL::Engine"->import(@methods);
can_ok(__PACKAGE__, @methods);
