#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 01_by_name.t'
#########################
use strict;
use warnings;

our $VERSION = "1.000";

BEGIN { $^W = 1 };
use Test::More "no_plan";
use Scalar::Util qw(tainted);

use WEC::SSL::Engine
;

# Hopefully we have at least the dynamic engine available

{
    package Eng;
    our @ISA = qw(WEC::SSL::Engine);
}

my @struct_refs = map {
    name	=> $_->name,
    struct	=> eval { $_->_structure_refcount },
    func	=> eval { $_->_function_refcount },
}, WEC::SSL::EngineList->all;
{
    my $taint = substr("$0$^X", 0, 0);
    my $engine;

    $engine = WEC::SSL::Engine->by_name("dynamic");
    isa_ok($engine, "WEC::SSL::Engine", "Check basic creation call");
    is($engine->taint ? 1 : 0, 0);
    is(tainted($engine) ? 1 : 0, 0);

    $engine = Eng->by_name("dynamic");
    isa_ok($engine, "Eng", "Check basic inheretance on creation");
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
}
is_deeply([map {
    name	=> $_->name,
    struct	=> eval { $_->_structure_refcount },
    func	=> eval { $_->_function_refcount },
}, WEC::SSL::EngineList->all], \@struct_refs);
