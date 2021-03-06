#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 00_load.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

BEGIN { $^W = 1 };
use Test::More "no_plan";

use_ok('WEC::SSL') || BAIL_OUT("Cannot even use WEC::SSL");
eval { diag("Tests use " . WEC::SSL::openssl_version()) };
