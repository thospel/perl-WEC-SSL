#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 08_filename.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Rand
;

my @methods = qw(filename);
can_ok("WEC::SSL::Rand", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

delete $ENV{RANDFILE};
my $str = WEC::SSL::Rand::filename;
ok($str);
ok(!tainted($str));

$ENV{RANDFILE} = "foo/bar";
$str = WEC::SSL::Rand::filename;
is($str, "foo/bar");
ok(!tainted($str));

delete $ENV{RANDFILE};

"WEC::SSL::Rand"->import(@methods);
can_ok(__PACKAGE__, @methods);
