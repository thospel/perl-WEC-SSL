#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 91_print_hex.t'

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
    my $result = $val->print_hex(@_);
    select($old_fh);
    close($fh) || die "Could not close $out_file: $!";
    return $result;
}

sub fh_print {
    my $val = shift;
    open(my $fh, ">", $out_file) || die "Could not create $out_file: $!";
    my $result = $val->print_hex($fh, @_);
    close($fh) || die "Could not close $out_file: $!";
    return $result;
}

my @methods = qw(print_hex);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($val, $result, $fh);

for my $nr ([-26, "-1a"], [-1, "-1"], [0, "0"], [1, "1"], [26, "1a"],
            ["-" . "123456789" x 100, "-693a27f23df3e7b66887d0753b0efe6716cb37fbf0e835359aae253ceeb59be71c5be71093e53c2a7d252a1bef9ef54cfcb5a50b19b18d66cc70bb7056ed22d0f02e3ca11673e2481557f229503c625ab8b2ae547b508b85f6793db43f29ed1c9e5c9157dd14b7487dab9abdf5608c5076aad39dcb780743b44eff83a2940f7507c91dff635c2390971b2ae62e439686e284aa7c957fa053cc32d8cf8fe6c7e9ec7351e6088e64da1a2cc8035a214186c8f42043119d1e468c0bf495806a2a9196fe66331b4026c1c6b7fd5a045e853de5d0c2aa3b0340331546e66ca8ca589a30419abf5c38a20a5c323d866a774a49e36b8c58c06e60bc9fd6b453fb84dafdced22aa8e3dfa082ce3e3e2ca649ac04817ec5c123e0b761ab103f780c014f021bbeb7ea3b86e0ca1c833e38ef5c897a6d7e1f4a2398c490b3d65e2f45c7fae402d1df1698b6fddb185481664871c2664bfd1686b2b3372783f1856f6247a3f8437a2818f68b7c4ea13a5f57b73c72870b684045f15"]) {
    $val = Big->new($nr->[0]);
    $result = default_print($val);
    is($result, 1);
    is(slurp(), $nr->[1]);

    $val = Big->new($nr->[0]);
    $result = fh_print($val);
    is($result, 1);
    is(slurp(), $nr->[1]);
}

# print to literal handle
$val = Big->new(28);
open(local *FH, ">", $out_file) || die "Could not create $out_file: $!";
$result = WEC::SSL::BigInt::print_hex($val, FH);
close(FH) || die "Could not close $out_file: $!";
is(slurp(), "1c");
is($result, 1);

# error print
my @warnings;
$SIG{__WARN__} = sub { push @warnings, join("", @_) };
$val = Big->new(28);
$result = WEC::SSL::BigInt::print_hex($val, FH);
is($result, undef);
is(@warnings, 1);
like($warnings[0], qr/^print\(\) on unopened filehandle FH at /i);

unlink($out_file);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
