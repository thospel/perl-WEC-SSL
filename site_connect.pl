#!/usr/bin/perl -w
use strict;
use Data::Dumper;
use Devel::Peek;

use FindBin qw($Bin);
use lib "$Bin/blib/lib", "$Bin/blib/arch";

use IO::Socket::INET;
use WEC::SSL;
use WEC::SSL::BigInt;

my $host = shift || "www.amazon.com";
my $socket = IO::Socket::INET->new(PeerAddr => $host,
                                   PeerPort => 'https(443)') ||
    die "Could not connect to $host (possibly $!)";

print STDERR "Connected to $host:443\n";

eval {
    print STDERR "ENGINE_METHOD_RSA=", WEC::SSL::Engine::METHOD_RSA(), "\n";
    my $encrypt = WEC::SSL::Encrypt->new(cipher => "aes-256-cbc", 
                                         key => "fun");
    print STDERR $encrypt->key_length, "\n";
    print STDERR $encrypt->iv_length,  "\n";
    print STDERR $encrypt->block_size, "\n";
    print STDERR unpack("H*", my $c1 = $encrypt->update("a" x 42)), "\n";
    print STDERR unpack("H*", my $c2 = $encrypt->finish), "\n";

    my $decrypt = WEC::SSL::Decrypt->new(cipher => "aes-256-cbc", 
                                         key => "fun");
    print STDERR $decrypt->update($c1), "\n";
    print STDERR $decrypt->update($c2), "\n";
    print STDERR $decrypt->finish, "\n";

    my $hash = WEC::SSL::DigestContext->new(digest => "sha256");
    $hash->update("foo\n");
    print STDERR unpack("H*", $hash->finish), "\n";

    my $hmac = WEC::SSL::HMAC->new(digest => "sha256", key => "waf");
    $hmac->update("foo\n");
    print STDERR unpack("H*", $hmac->finish), "\n";

    my %engines;
    tie %engines, "WEC::SSL::EngineList";
    my $aep = WEC::SSL::Engine->new("aep");
    print STDERR "Engine id=", $aep->id, ", name=", $aep->name, "\n";
    print STDERR "it Engine=$_\n" for keys %engines;
    print STDERR "Engine $_ exists: ", exists $engines{$_}, "\n" for "dynamic", "aep", "fun";
    print STDERR "Ignore Error: $_\n" while $_ = WEC::SSL::error_line();

    my $dynamic = WEC::SSL::Engine->new("dynamic");
    print STDERR "flags=", $dynamic->flags, "\n";
    $dynamic->for_RSA;
    print STDERR "flags=", $dynamic->flags, "\n";
    # print STDERR "RSA engine=", WEC::SSL::Engine->DH, "\n";

    print STDERR "RAND filename=", WEC::SSL::Rand::filename(), "\n";
    print STDERR "read ", WEC::SSL::Rand::load_file("/home/ton/.rnd", 28), " bytes\n";
    print STDERR "wrote ", WEC::SSL::Rand::write_file("/dev/urandom"), " bytes\n";
    # print STDERR "Got random bytes: ", unpack("H*", WEC::SSL::Rand::bytes(1024)), "\n" for 1..1;
    print STDERR "Will load EGD\n";
    WEC::SSL::Rand::try_load_from_egd("/var/run/egd-pool");
    print STDERR "Loaded EGD\n";
    print STDERR unpack("H*", WEC::SSL::Rand::try_fetch_from_egd("/var/run/egd-pool")), "\n";

    my $a = WEC::SSL::BigInt->new("123456789123456789");
    my $b = WEC::SSL::BigInt->new(3);
    my $one  = WEC::SSL::BigInt->new(1);
    my $zero = WEC::SSL::BigInt->new(0);
    print STDERR "a=", $a->to_decimal, "\n";
    print STDERR "a=$a\n";
    my $sum = $a+$a;
    print STDERR "sum=$sum\n";
    print STDERR $sum->to_decimal, "\n";
    my $c = $a;
    print STDERR "Copied c\n";
    $a += $b;
    print STDERR "a=$a\n";
    $a = 1 - $a;
    print STDERR "c=$c\n";
    print STDERR "a=$a\n";
    my $mul = $a * $a;
    print STDERR "mul=$mul\n";
    $a = WEC::SSL::BigInt->new(87);
    my $g = $a->gcd(9);
    print STDERR "gcd=$g\n";
    $a **= 4;
    print "a=$a\n";
    print "bool a is ", $a ? 1 : 0, "\n";
    print "bool zero is ", $zero ? 1 : 0, "\n";
    print "int a=", int($a**999), "\n";
    print "a < zero: ", $a < $zero, "\n";
    print "zero < a: ", $zero < $a, "\n";
    print "a < 0: ", $a < 0, "\n";
    print "0 < a: ", 0 < $a, "\n";
    $a = -$a;
    print "lshift $a,  1 = ", $a <<  1, "\n";
    print "lshift $a, -1 = ", $a << -1, "\n";
    print "lshift $a,  0 = ", $a <<  0, "\n";
    print "rshift $a,  1 = ", $a >>  1, "\n";
    print "rshift $a, -1 = ", $a >> -1, "\n";
    print "rshift $a,  0 = ", $a >>  0, "\n";
    print "lshift1 $a = ", $a->lshift1, "\n";
    print "rshift1 $a = ", $a->rshift1, "\n";
    print "negate $a = ", $a->negate, "\n";
    print "abs $a = ", $a->abs, "\n";
    my $na = -$a;
    print "na = $na\n";
    print "negate $na = ", $na->negate, "\n";
    print "abs $na = ", $na->abs, "\n";
    print "abs $zero = ", $zero->abs, "\n";
    $a = $a ** 21 x 3;
    print "a = $a\n";
    die "";
    exit;

    my $context = WEC::SSL::SSLContext->new(verification_directory => "/etc/ssl/certs");
    $context->add_verification_file("/home/ton/legian.PEM");
    my $socket_bio = WEC::SSL::Bio::Socket->new($socket);
    my $ssl = eval {
        $context->connect(read_bio => $socket_bio, write_bio => $socket_bio) };
    if ($@) {
        my $err = $@;
        my ($x509, $depth, $code) = $context->verify_error;
        printf(STDERR "Depth %d, code=%s\nissuer=%s\nsubject=%s\n", 
               $depth, $code, $x509->issuer_string, $x509->subject_string);
        my $out = WEC::SSL::Bio::Socket->new(\*STDOUT);
        $x509->PEM_write(bio => $out
                         # , cipher => "aes-256-cbc", key => "zzzz"
                         );
        die $err;
    }
    $ssl->write("GET / HTTP/1.0\r\n\r\n");
    print "_=<$_>\n" while $_=$ssl->get(100);
};
print "Failed: $@" if $@;
print "Error: $_\n" while $_ = WEC::SSL::error_line();
print STDERR "Line ", __LINE__, "\n";
