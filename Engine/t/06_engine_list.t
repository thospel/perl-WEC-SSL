#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 06_engine_list.t'
#########################
our $VERSION = "1.000";

use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";
use Scalar::Util qw(tainted);

use WEC::SSL qw(feature_taint);
use WEC::SSL::EngineList;

{
    package List;
    our @ISA = qw(WEC::SSL::EngineList);
}

my @methods = qw(all);
can_ok("List", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my @struct_refs = map {
    name	=> $_->name,
    struct	=> eval { $_->_structure_refcount },
    func	=> eval { $_->_function_refcount },
}, WEC::SSL::EngineList->all;
{
    my @engines = List->all;
    ok(@engines, "We should at least have the dynamic engine");
    my @dynamic = grep $_->name eq "dynamic", @engines;
    is(@dynamic, 1, "Exectly one dynamic engine");
    isa_ok($dynamic[0], "WEC::SSL::Engine");

    my $nr = List->all;
    is($nr, @engines, "Scalar call should count all engines");

    tie my %engines, 'WEC::SSL::EngineList';
    while (my ($name, $engine) = each %engines) {
        ok($name, "Engine named $name");
        isa_ok($engine, "WEC::SSL::Engine");
        my $e = shift @engines;
        if ($e) {
            is($engine->name, $e->name, "Equal names");
        } else {
            fail("Unexpected extra engine " . $engine->name);
        }
    }
    ok(!@engines, "Unexpected missing engines");

    ok(exists $engines{dynamic}, "The dynamic engine exists");
    ok(!exists $engines{chr 0xa0}, "The \\xa0 engine does not exist");
    my $dynamic = "dynamic";
    utf8::upgrade($dynamic);
    ok(exists $engines{$dynamic}, 
       "The dynamic engine still exists even if asked for with an utf8 string");
    ok(!exists $engines{"dynamic\0"}, "The dynamic\\0 engine does not exist");

SKIP: {
    skip "No taint support" unless feature_taint();

    my $taint =substr("$0$^X", 0, 0);
    my $engine = $engines{"dynamic$taint"};
    ok(tainted($engine));
    ok($engine->taint);
    }
}
is_deeply([map {
    name	=> $_->name,
    struct	=> eval { $_->_structure_refcount },
    func	=> eval { $_->_function_refcount },
}, WEC::SSL::EngineList->all], \@struct_refs);

"WEC::SSL::EngineList"->import(@methods);
can_ok(__PACKAGE__, @methods);
