#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 093_bio_print_HEX.t'
# No taint checking in this test

## no critic (ProhibitUselessNoCritic ProhibitMagicNumbers)
use strict;
use warnings;
BEGIN { $^W = 1 };
use Test::More "no_plan";

use WEC::SSL::BigInt;
    use WEC::SSL::Bio::Memory;
;

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my $memory = WEC::SSL::Bio::Memory->new;
my @methods = qw(bio_print_HEX);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

my ($val, $result, $fh);

for my $nr ([-26, "-1A"], [-1, "-1"], [0, "0"], [1, "1"], [26, "1A"],
            ["-" . "123456789" x 100, "-693A27F23DF3E7B66887D0753B0EFE6716CB37FBF0E835359AAE253CEEB59BE71C5BE71093E53C2A7D252A1BEF9EF54CFCB5A50B19B18D66CC70BB7056ED22D0F02E3CA11673E2481557F229503C625AB8B2AE547B508B85F6793DB43F29ED1C9E5C9157DD14B7487DAB9ABDF5608C5076AAD39DCB780743B44EFF83A2940F7507C91DFF635C2390971B2AE62E439686E284AA7C957FA053CC32D8CF8FE6C7E9EC7351E6088E64DA1A2CC8035A214186C8F42043119D1E468C0BF495806A2A9196FE66331B4026C1C6B7FD5A045E853DE5D0C2AA3B0340331546E66CA8CA589A30419ABF5C38A20A5C323D866A774A49E36B8C58C06E60BC9FD6B453FB84DAFDCED22AA8E3DFA082CE3E3E2CA649AC04817EC5C123E0B761AB103F780C014F021BBEB7EA3B86E0CA1C833E38EF5C897A6D7E1F4A2398C490B3D65E2F45C7FAE402D1DF1698B6FDDB185481664871C2664BFD1686B2B3372783F1856F6247A3F8437A2818F68B7C4EA13A5F57B73C72870B684045F15"]) {
    $val = Big->new($nr->[0]);
    $result = $val->bio_print_HEX($memory);
    is($result, 1);
    is($memory->get(1e9), $nr->[1]);
}

# error print
$val = Big->new(28);
$result = eval { $val->bio_print_HEX(undef) };
like($@, qr/^Undefined bio argument at /i);

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
