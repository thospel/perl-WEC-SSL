#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 01_X509.t'
use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::X509;

pass("dummy");
