#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 03_taint.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util ();
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Utils
;

{
    package Big;
    our @ISA = qw(WEC::SSL::Utils);
}

my @methods = qw(taint);
can_ok("WEC::SSL::Utils", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($result, $tmp);

$tmp = $result = -28;
ok(!WEC::SSL::Utils::taint($result));
ok(!WEC::SSL::Utils::taint($result, 1));
ok(WEC::SSL::Utils::taint($result, 1));
ok(WEC::SSL::Utils::taint($result));
ok(Scalar::Util::tainted($result));
ok(!Scalar::Util::tainted($tmp));
ok(WEC::SSL::Utils::taint($result, 0));
ok(!WEC::SSL::Utils::taint($result, 0));
ok(!WEC::SSL::Utils::taint($result));
ok(!Scalar::Util::tainted($result));
ok(!Scalar::Util::tainted($tmp));
WEC::SSL::Utils::taint($result, 28);
ok(WEC::SSL::Utils::taint($result));
WEC::SSL::Utils::taint($result, undef);
ok(!WEC::SSL::Utils::taint($result));
WEC::SSL::Utils::taint($result, []);
ok(WEC::SSL::Utils::taint($result));
WEC::SSL::Utils::taint($result, "0");
ok(!WEC::SSL::Utils::taint($result));

$tmp = "abc14";
WEC::SSL::Utils::taint($tmp, 1);
WEC::SSL::Utils::taint($result, $tmp);
ok(WEC::SSL::Utils::taint($result));

$tmp = undef;
WEC::SSL::Utils::taint($tmp, 1);
eval { WEC::SSL::Utils::taint($result, $tmp) };
like($@, qr/^Turning tainting off using a tainted value at /i);
ok(WEC::SSL::Utils::taint($result));

is($result, -28);

"WEC::SSL::Utils"->import(@methods);
can_ok(__PACKAGE__, @methods);
