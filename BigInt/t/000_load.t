#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 000_load.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

BEGIN { $^W = 1 };
use Test::More "no_plan";

for my $module (qw(WEC::SSL::BigInt WEC::SSL::Reciprocal WEC::SSL)) {
    use_ok($module) || BAIL_OUT("Cannot even use $module");
}
