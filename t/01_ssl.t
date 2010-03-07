#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 01_ssl.t'
use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok('WEC::SSL') };

my @methods = qw(openssl_version feature_sensitive feature_taint feature_magic);
can_ok("WEC::SSL", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}
WEC::SSL->import(@methods);
can_ok(__PACKAGE__, @methods);

my $version = WEC::SSL::openssl_version();
my $num_v = $version + 0;
ok($num_v >= 0x00908000);
my $string_v = "$version";
ok($string_v =~ /OpenSSL/i);

eval { WEC::SSL::feature_sensitive() };
pass("has feature_sensitive");

eval { WEC::SSL::feature_taint() };
pass("has feature_taint");

eval { WEC::SSL::feature_magic() };
pass("has feature_magic");
