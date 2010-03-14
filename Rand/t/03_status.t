#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 03_status.t'
#########################
our $VERSION = "1.000";

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Rand
;

my @methods = qw(status);
can_ok("WEC::SSL::Rand", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $rc = WEC::SSL::Rand::status;
ok(!tainted($rc));
WEC::SSL::Rand::seed("a" x 1024);
$rc = WEC::SSL::Rand::status;
ok($rc);
ok(!tainted($rc));

"WEC::SSL::Rand"->import(@methods);
can_ok(__PACKAGE__, @methods);
