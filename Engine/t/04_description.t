#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 04_description.t'
use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";
use Scalar::Util qw(tainted);

use WEC::SSL::Engine
;

# Hopefully we have at least the dynamic engine available

{
    package Big;
    our @ISA = qw(WEC::SSL::Engine);
}

my $taint = substr("$0$^X", 0, 0);
my ($engine, $description);

$engine = Big->by_name("dynamic");
isa_ok($engine, "Big", "Check basic inheretance on creation");
$description = $engine->description;
is($description, "Dynamic engine loading support");
is(tainted($description) ? 1 : 0, 0);

$engine = WEC::SSL::Engine->by_name("dynamic" . $taint);
$description = $engine->description;
is($description, "Dynamic engine loading support");
is(tainted($description) ? 1 : 0, 1);
