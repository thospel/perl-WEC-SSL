#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 09_try_load_file.t'
#########################
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util qw(tainted);
use FindBin qw($Bin);
use POSIX qw(ENOENT);

BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Rand;
    use WEC::SSL::BigInt;
;

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(try_load_file);
can_ok("WEC::SSL::Rand", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my $out = "out";
$Bin =~ /(.*)/s;
my $out_file = "$1/$out";

sub spew {
    open(my $fh, ">", $out_file) || die "Could not creat $out_file: $!";
    binmode $fh;
    print($fh @_) || die "Error writing to $out_file";
    close($fh) || die "Could not close $out_file: $!";
}

my $read;

spew("foo");
$read = WEC::SSL::Rand::try_load_file($out_file);
is($read, 3);
ok(tainted($read));
$read = WEC::SSL::Rand::try_load_file($out_file, 0);
is($read, 0);
ok(tainted($read));
$read = WEC::SSL::Rand::try_load_file($out_file, 2);
is($read, 2);
ok(tainted($read));
$read = WEC::SSL::Rand::try_load_file($out_file . $taint);
is($read, 3);
ok(tainted($read));
$read = WEC::SSL::Rand::try_load_file($out_file . $taint, 2);
is($read, 2);
ok(tainted($read));
$read = WEC::SSL::Rand::try_load_file($out_file, 2 . $taint);
is($read, 2);
ok(tainted($read));

$read = WEC::SSL::Rand::try_load_file($out_file, WEC::SSL::BigInt->new(2));
is($read, 2);

spew("ab\r\ncd\r\n");
$read = WEC::SSL::Rand::try_load_file($out_file);
is($read, 8);

$read = eval { WEC::SSL::Rand::try_load_file($out_file, -1) };
like($@, qr/^max_bytes -1 is negative at /i);

$read = eval { WEC::SSL::Rand::try_load_file($out_file, ~0 * 2) };
like($@, qr/^max_bytes .+ out of range at /i);

$read = eval { WEC::SSL::Rand::try_load_file($out_file, WEC::SSL::BigInt->new(-1)) };
like($@, qr/^max_bytes is negative at /i);

$read = eval { WEC::SSL::Rand::try_load_file($out_file, WEC::SSL::BigInt->new(~0 * 2)) };
like($@, qr/^max_bytes out of range at /i);

unlink($out_file) || $! == ENOENT || die "Could not unlink '$out_file': $!";
$read = WEC::SSL::Rand::try_load_file($out_file);
is($read, 0);

"WEC::SSL::Rand"->import(@methods);
can_ok(__PACKAGE__, @methods);
