#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 03_taint.t'
use strict;
use warnings;
use Scalar::Util ();
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok("WEC::SSL::Utils") };

{
    package Big;
    our @ISA = qw(WEC::SSL::Utils);
}

my @methods = qw(tainted);
can_ok("WEC::SSL::Utils", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$tmp = $result = -28;
ok(!WEC::SSL::Utils::tainted($result));
ok(!WEC::SSL::Utils::tainted($result, 1));
ok(WEC::SSL::Utils::tainted($result, 1));
ok(WEC::SSL::Utils::tainted($result));
ok(Scalar::Util::tainted($result));
ok(!Scalar::Util::tainted($tmp));
ok(WEC::SSL::Utils::tainted($result, 0));
ok(!WEC::SSL::Utils::tainted($result, 0));
ok(!WEC::SSL::Utils::tainted($result));
ok(!Scalar::Util::tainted($result));
ok(!Scalar::Util::tainted($tmp));
WEC::SSL::Utils::tainted($result, 28);
ok(WEC::SSL::Utils::tainted($result));
WEC::SSL::Utils::tainted($result, undef);
ok(!WEC::SSL::Utils::tainted($result));
WEC::SSL::Utils::tainted($result, []);
ok(WEC::SSL::Utils::tainted($result));
WEC::SSL::Utils::tainted($result, "0");
ok(!WEC::SSL::Utils::tainted($result));

$tmp = "abc14";
WEC::SSL::Utils::tainted($tmp, 1);
WEC::SSL::Utils::tainted($result, $tmp);
ok(WEC::SSL::Utils::tainted($result));

$tmp = undef;
WEC::SSL::Utils::tainted($tmp, 1);
eval { WEC::SSL::Utils::tainted($result, $tmp) };
like($@, qr/^Turning tainting off using a tainted value at /i);
ok(WEC::SSL::Utils::tainted($result));

is($result, -28);

"WEC::SSL::Utils"->import(@methods);
can_ok(__PACKAGE__, @methods);
