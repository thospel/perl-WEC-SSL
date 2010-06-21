package WEC::SSL::Montgomery;
use 5.006001;
use strict;
use warnings;

our $VERSION = "1.000";

require WEC::SSL::BigInt;

use Exporter::Tidy
    other => [qw(new mod_mul from to)];

1;
__END__

=head1 NAME

WEC::SSL::Montgomery - Montgomery reduction for faster modular arithmetic

=head1 SYNOPSIS


=head1 DESCRIPTION

Montgomery multiplication leads to a faster form of modular multiplication.
It works by taking a modulus m and calculating an R such that gcd(m, R) = 1.
This is usually done by taking R = b**r where b is some natural wordsize
(like 2**32) and r is the smallest integer such that R > m. (this obviously
only works if m is odd). Then R**-1 (mod m) is determined (which will be
an integer, we're doing modular arithmetic here).

A montgomery multiplication of a and b is then a*b*R**-1 mod m. The crucial
part is that this can be done quite fast.

The final step is how to do a normal multiplication of aa and bb. The basic
idea is to first convert these to "montgomery form"

  a=aa*R mod m
 and
  b=bb*R mod m.

Montgomery multiplication then gives

  a*b*R**-1 mod m = aa*bb*R mod m

which is the "montgomery form" of the wanted result.

So you can do many modular multiplies (for example for a modular
exponentiation) by first converting your numbers to montgomery form, then doing
all needed multiplications as montgomery multiplications and finally convert
back to normal form.

=head1 METHODS

=over 4

=back

=head1 EXPORT

Except for the constructors everything is exportable, but nothing is exported
by default. It uses L<Exporter::Tidy|Exporter::Tidy> for the exports, so
you can import methods under modified (prefixed) names.

=head1 SEE ALSO

L<WEC::SSL::Errors>,
L<WEC::SSL::BigInt>,
L<WEC::SSL::Montgomery>

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL-Montgomery@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
