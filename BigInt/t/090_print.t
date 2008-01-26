#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 90_print.t'

# No taint checking in this test

use strict;
use warnings;
use FindBin qw($Bin);
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok("WEC::SSL::BigInt") };

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my $out = "out";
my $out_file = "$Bin/$out";

sub slurp {
    my $file = $out_file;
    open(my $fh, "<", $file) || die "Could not open $file: $!";
    my $rc = read($fh, my $slurp, 1 + -s $fh);
    die "File '$file' is still growing" if
        $rc &&= read($fh, $slurp, 1, length $slurp);
    die "Error reading from '$file': $!" if !defined $rc;
    close($fh) || die "Error while closing '$file': $!";
    return $slurp;
}

sub default_print {
    my $val = shift;
    open(my $fh, ">", $out_file) || die "Could not create $out_file: $!";
    my $old_fh = select($fh);
    my $result = $val->print(@_);
    select($old_fh);
    close($fh) || die "Could not close $out_file: $!";
    return $result;
}

sub fh_print {
    my $val = shift;
    open(my $fh, ">", $out_file) || die "Could not create $out_file: $!";
    my $result = $val->print($fh, @_);
    close($fh) || die "Could not close $out_file: $!";
    return $result;
}

my @methods = qw(print);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($val, $result, $fh);

for my $nr (-26, -1, 0, 1, 26, "-" . "123456789" x 100) {
    $val = Big->new($nr);
    $result = default_print($val);
    is($result, 1);
    is(slurp(), $nr);

    $val = Big->new($nr);
    $result = fh_print($val);
    is($result, 1);
    is(slurp(), $nr);
}

# print to literal handle
$val = Big->new(28);
open(local *FH, ">", $out_file) || die "Could not create $out_file: $!";
$result = WEC::SSL::BigInt::print($val, FH);
close(FH) || die "Could not close $out_file: $!";
is(slurp(), 28);
is($result, 1);

# error print
my @warnings;
$SIG{__WARN__} = sub { push @warnings, join("", @_) };
$val = Big->new(28);
$result = WEC::SSL::BigInt::print($val, FH);
is($result, undef);
is(@warnings, 1);
like($warnings[0], qr/^print\(\) on unopened filehandle FH at /i);

unlink($out_file);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
