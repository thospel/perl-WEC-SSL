#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 12_write_file.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Scalar::Util qw(tainted);
use FindBin qw($Bin);
use POSIX qw(ENOENT);
use Fcntl ':mode';

BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Rand;
    use WEC::SSL::BigInt;
;

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(write_file RAND_DATA);
can_ok("WEC::SSL::Rand", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

# Fake seeding the PRNG
WEC::SSL::Rand::seed("1" x 1024);

$Bin =~ /(.*)/s;
my $out_file = "$1/out";
my $out_dir  = "$1/out_dir";

sub spew {
    open(my $fh, ">", $out_file) || die "Could not creat $out_file: $!";
    binmode $fh;
    print($fh @_) || die "Error writing to $out_file";
    close($fh) || die "Could not close $out_file: $!";
}

my $written;
unlink($out_file) || $! == ENOENT || die "Could not unlink '$out_file': $!";
umask 0322;
$written = WEC::SSL::Rand::write_file($out_file);
is($written, WEC::SSL::Rand::RAND_DATA, "RAND_DATA equals $written");
ok($written > 500);
ok(!tainted($written));
my $rand_data = $written;
my @stat = stat($out_file) or die "Could not stat $out_file: $!";
is(S_IMODE($stat[2]), 0400);

chmod(0700, $out_file) || die "Could not chmod $out_file: $!";
@stat = stat($out_file) or die "Could not stat $out_file: $!";
is(S_IMODE($stat[2]), 0700);
spew("a" x 2 x $rand_data);
$written = WEC::SSL::Rand::write_file($out_file);
is($written, $rand_data, "We trucate the old data");
ok(!tainted($written));
@stat = stat($out_file) or die "Could not stat $out_file: $!";
is(S_IMODE($stat[2]), 0400);

eval { WEC::SSL::Rand::write_file($out_file . $taint) };
like($@, qr/^Insecure dependency in sysopen while running with -T switch at /i);
umask 022;
unlink($out_file) || $! == ENOENT || die "Could not unlink '$out_file': $!";

$written = WEC::SSL::Rand::write_file($out_file, 0666);
is($written, WEC::SSL::Rand::RAND_DATA, "RAND_DATA equals $written");
is($written, $rand_data);
ok(!tainted($written));
@stat = stat($out_file) or die "Could not stat $out_file: $!";
is(S_IMODE($stat[2]), 0644);

chmod(0700, $out_file) || die "Could not chmod $out_file: $!";

$written = WEC::SSL::Rand::write_file($out_file, 0666);
is($written, WEC::SSL::Rand::RAND_DATA, "RAND_DATA equals $written");
is($written, $rand_data);
ok(!tainted($written));
@stat = stat($out_file) or die "Could not stat $out_file: $!";
is(S_IMODE($stat[2]), 0644);

rmdir($out_dir) || $! == ENOENT || die "Could not rmdir($out_dir): $!";
mkdir($out_dir) || die "Could not mkdir($out_dir): $!";
$written = eval { WEC::SSL::Rand::write_file($out_dir) };
like($@, qr/^Could not create '\Q$out_dir\E': .+ at /i);
rmdir($out_dir) || $! == ENOENT || die "Could not rmdir($out_dir): $!";

"WEC::SSL::Rand"->import(@methods);
can_ok(__PACKAGE__, @methods);
