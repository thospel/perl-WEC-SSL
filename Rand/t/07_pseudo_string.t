#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T 07_pseudo_string.t'
use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::Rand
;

my $taint = substr("$^X$0", 0, 0);

my @methods = qw(pseudo_string);
can_ok("WEC::SSL::Rand", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

# Fake seeding the PRNG
WEC::SSL::Rand::seed("1" x 1024);

my $str = WEC::SSL::Rand::pseudo_string("A");
is($str, "A");
ok(!tainted($str));

$str = WEC::SSL::Rand::pseudo_string("A", 3);
is($str, "AAA");
ok(!tainted($str));

$str = WEC::SSL::Rand::pseudo_string("A-A", 3);
is($str, "AAA");
ok(!tainted($str));
ok(!utf8::is_utf8($str));

$str = WEC::SSL::Rand::pseudo_string(chr(256), 3);
is($str, chr(256) x 3);
ok(!tainted($str));
ok(utf8::is_utf8($str));

$str = WEC::SSL::Rand::pseudo_string(chr(256), 0);
is($str, "");
ok(!tainted($str));
ok(utf8::is_utf8($str));

$str = WEC::SSL::Rand::pseudo_string("A", 0);
is($str, "");
ok(!tainted($str));

$str = eval { WEC::SSL::Rand::pseudo_string("A", -1) };
like($@, qr/^length -1 is negative at /i);

$str = eval { WEC::SSL::Rand::string("Z-A") };
like($@, qr/^Invalid range at /i);

$str = eval "WEC::SSL::Rand::pseudo_string()";
like($@, qr/^Not enough arguments for WEC::SSL::Rand::pseudo_string at /i);

my @counts;
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string("01", 16);
    die "Weird result $str" if $str !~ /^[01]{16}\z/;
    $counts[$_] += substr($str, $_, 1) for 0..15;
}
for (0..15) {
    ok($counts[$_] > 1000/2/2);
}

@counts = ();
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string("0-1", 16);
    die "Weird result $str" if $str !~ /^[01]{16}\z/;
    $counts[$_] += substr($str, $_, 1) for 0..15;
}
for (0..15) {
    ok($counts[$_] > 1000/2/2);
}

@counts = ();
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string("1101", 16);
    die "Weird result $str" if $str !~ /^[01]{16}\z/;
    $counts[$_] += substr($str, $_, 1) for 0..15;
}
for (0..15) {
    ok($counts[$_] > 1000*3/4/2);
}

my %counts;
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string("A-Z", 16);
    die "Weird result $str" if $str !~ /^[A-Z]{16}\z/;
    $counts{substr($str, $_, 1)}++ for 0..15;
}
is_deeply([sort keys %counts], ["A".."Z"]);

%counts = ();
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string("A-Qt-z", 16);
    die "Weird result $str" if $str !~ /^[A-Qt-z]{16}\z/;
    $counts{substr($str, $_, 1)}++ for 0..15;
}
is_deeply([sort keys %counts], [sort "A".."Q", "t".."z"]);

%counts = ();
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string("A-", 16);
    die "Weird result $str" if $str !~ /^[A-]{16}\z/;
    $counts{substr($str, $_, 1)}++ for 0..15;
}
is_deeply([sort keys %counts], [sort "A", "-"]);

%counts = ();
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string("-A", 16);
    die "Weird result $str" if $str !~ /^[A-]{16}\z/;
    $counts{substr($str, $_, 1)}++ for 0..15;
}
is_deeply([sort keys %counts], [sort "A", "-"]);

%counts = ();
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string('A\\-Q', 16);
    die "Weird result $str" if $str !~ /^[AQ-]{16}\z/;
    $counts{substr($str, $_, 1)}++ for 0..15;
}
is_deeply([sort keys %counts], [sort "A", "Q", "-"]);

%counts = ();
for (1..1000) {
    my $str = WEC::SSL::Rand::pseudo_string('A\\\\', 16);
    die "Weird result $str" if $str !~ /^[A\\]{16}\z/;
    $counts{substr($str, $_, 1)}++ for 0..15;
}
is_deeply([sort keys %counts], [sort "A", "\\"]);

for (['\n' => "\n"], 
     ['\t' => "\t"], 
     ['\f' => "\f"], 
     ['\r' => "\r"], 
     ['\a' => "\a"], 
     ['\b' => "\b"], 
     ['\e' => "\e"], 
     ) {
    my $str = WEC::SSL::Rand::pseudo_string($_->[0], 3);
    is($str, $_->[1] x 3);
}

$str = eval { WEC::SSL::Rand::pseudo_string('A\\', 8) };
like($@, qr/^Trailing \\ at/);

$str = WEC::SSL::Rand::pseudo_string("A", 4 . $taint);
is($str, "AAAA");
ok(tainted($str));

$str = WEC::SSL::Rand::pseudo_string("A" . $taint, 4);
is($str, "AAAA");
ok(tainted($str));

"WEC::SSL::Rand"->import(@methods);
can_ok(__PACKAGE__, @methods);
