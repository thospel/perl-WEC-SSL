#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 00_load.t'
use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";

for my $module (qw(WEC::SSL::X509 WEC::SSL)) {
    use_ok($module) || BAIL_OUT("Cannot even use $module");
}
