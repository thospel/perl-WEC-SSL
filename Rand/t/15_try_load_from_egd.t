#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 15_try_load_from_egd.t'
#########################
our $VERSION = "1.000";

use strict;
use warnings;
use Scalar::Util qw(tainted);
use FindBin qw($Bin);
use POSIX qw(ENOENT);

BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Rand
;

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(try_load_from_egd egd_entropy);
can_ok("WEC::SSL::Rand", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

$Bin =~ /(.*)/s;
my $out_file = "$1/out";
my $egd_file = "$1/egd";

sub spew {
    open(my $fh, ">", $out_file) || die "Could not creat $out_file: $!";
    binmode $fh;
    print($fh @_) || die "Error writing to $out_file";
    close($fh) || die "Could not close $out_file: $!";
}

unlink($out_file) || $! == ENOENT || die "Could not unlink '$out_file': $!";
spew($out_file, "");

my $str = WEC::SSL::Rand::try_load_from_egd($out_file, 5);
is($str, 0);
ok(!tainted($str));

my $entropy = eval { WEC::SSL::Rand::egd_entropy($egd_file) };
SKIP: {
    skip "egd file $egd_file doesn't really seem to be an egd device ($@)" if
        $@;
  SKIP: {
      skip "Not enough entropy" if $entropy < 5;
      my $e = $entropy;
      $str = WEC::SSL::Rand::try_load_from_egd($egd_file, 5);
      is($str, 5);
      ok(!tainted($str));
      # Can fail if some entropy immediately got added
      is(WEC::SSL::Rand::egd_entropy($egd_file), $e-5, 
         "Entropy is lowered due to fetch");
  }

    $str = WEC::SSL::Rand::try_load_from_egd($egd_file, 0);
    is($str, 0);
    ok(!tainted($str));

    $entropy = WEC::SSL::Rand::egd_entropy($egd_file);
  SKIP: {
      skip "Not enough entropy" if $entropy < 4;
      $str = WEC::SSL::Rand::try_load_from_egd($egd_file, 4 . $taint);
      is($str, 4);
      ok(tainted($str));
  }

    $entropy = WEC::SSL::Rand::egd_entropy($egd_file);
  SKIP: {
      skip "Not enough entropy" if $entropy < 300;
      $str = WEC::SSL::Rand::try_load_from_egd($egd_file, 300);
      is($str, 300);
      ok(!tainted($str));
  }

    $entropy = WEC::SSL::Rand::egd_entropy($egd_file);
  SKIP: {
      skip "Not enough entropy" if $entropy < 255;
      $str = WEC::SSL::Rand::try_load_from_egd($egd_file);
      is($str, 255);
      ok(!tainted($str));
  }

    $str = eval { WEC::SSL::Rand::try_load_from_egd($egd_file, -1) };
    like($@, qr/^nr_bytes -1 is negative at /i);

    $str = eval { WEC::SSL::Rand::try_load_from_egd($egd_file, ~0 * 2) };
    like($@, qr/^nr_bytes .+ out of range at /i);

    $str = eval { WEC::SSL::Rand::try_load_from_egd($egd_file . $taint, 4) };
    like($@, qr/^Insecure dependency in try_load_from_egd while running with -T switch at /i);
}

"WEC::SSL::Rand"->import(@methods);
can_ok(__PACKAGE__, @methods);
