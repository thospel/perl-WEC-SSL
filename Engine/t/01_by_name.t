#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 01_by_name.t'
use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";
use Scalar::Util qw(tainted);

BEGIN { use_ok('WEC::SSL::Engine') };

# Hopefully we have at least the dynamic engine available

{
    package Big;
    our @ISA = qw(WEC::SSL::Engine);
}

my $taint = substr("$0$^X", 0, 0);
my $engine;

$engine = WEC::SSL::Engine->by_name("dynamic");
isa_ok($engine, "WEC::SSL::Engine", "Check basic creation call");
is($engine->taint ? 1 : 0, 0);
is(tainted($engine) ? 1 : 0, 0);

$engine = Big->by_name("dynamic");
isa_ok($engine, "Big", "Check basic inheretance on creation");
is($engine->taint ? 1 : 0, 0);
is(tainted($engine) ? 1 : 0, 0);

$engine = eval { WEC::SSL::Engine->by_name("vcjkhsgkajnghnadjgankdnba") };
like($@, qr/no such engine \(id=vcjkhsgkajnghnadjgankdnba\) at /i, "Check basic failure");

$engine = WEC::SSL::Engine->by_name("dynamic" . $taint);
is($engine->taint ? 1 : 0, 1);
is(tainted($engine) ? 1 : 0, 1);

my $class = "WEC::SSL::Engine" . $taint;
$engine = $class->by_name("dynamic");
is($engine->taint ? 1 : 0, 1);
is(tainted($engine) ? 1 : 0, 1);
