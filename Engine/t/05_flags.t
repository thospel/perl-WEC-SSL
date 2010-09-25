#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 05_flags.t'
#########################
## no critic (ProhibitUselessNoCritic ProhibitMagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

BEGIN { $^W = 1 };
use Test::More "no_plan";
use Scalar::Util qw(tainted);

use WEC::SSL::Engine;

# Hopefully we have at least the dynamic engine available

{
    package Eng;
    our @ISA = qw(WEC::SSL::Engine);
}

my $taint = substr("$0$^X", 0, 0);

my @methods = qw(FLAGS_MALLOCED FLAGS_MANUAL_CMD_CTRL FLAGS_BY_ID_COPY);
can_ok("WEC::SSL::Engine", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($engine, $flags);

$engine = Eng->by_name("dynamic");
isa_ok($engine, "Eng", "Check basic inheretance on creation");
$flags = $engine->flags;
is($flags, WEC::SSL::Engine::FLAGS_BY_ID_COPY);
is(tainted($flags) ? 1 : 0, 0);

$engine = WEC::SSL::Engine->by_name("dynamic" . $taint);
$flags = $engine->flags;
is($flags, WEC::SSL::Engine::FLAGS_BY_ID_COPY);
is(tainted($flags) ? 1 : 0, 1);

eval { $engine->flags(WEC::SSL::Engine::FLAGS_BY_ID_COPY) };
like($@, qr/^Insecure dependency in 'flags' while running with -T switch at /i);
$engine = Eng->by_name("dynamic");
eval { $engine->flags(WEC::SSL::Engine::FLAGS_BY_ID_COPY() . $taint) };
like($@, qr/^Insecure dependency in 'flags' while running with -T switch at /i);
$flags = $engine->flags;
my $new_flags = $engine->flags(0);
is($new_flags, $flags);
is($engine->flags, 0);
$new_flags = $engine->flags(0);
is($new_flags, 0);
$new_flags = $engine->flags($flags);
is($new_flags, 0);
$new_flags = $engine->flags($flags);
is($new_flags, $flags);

"WEC::SSL::Engine"->import(@methods);
can_ok(__PACKAGE__, @methods);
