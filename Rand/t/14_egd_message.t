#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 4_egd_message.t'

use FindBin qw($Bin);

my $egd_file = "$Bin/egd";

use Test::More "no_plan";
pass("Dummy pass");
diag("\nThe EGD tests assume you have some EGD daemon running for socket
$egd_file.\n
The EGD tests can fail if you are using a daemon that only provides a small
entropy pool. In that case you might see a failures where a number is 
smaller than expected followed by zeros that are smaller than expected");

