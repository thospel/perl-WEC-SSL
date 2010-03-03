package WEC::SSL;
use 5.006001;
use strict;
use warnings;

our $VERSION = "1.000";

# Load XS prerequisites
require WEC::SSL::Utils;

use Exporter::Tidy
    other => [qw(openssl_version)];

1;
__END__

=head1 NAME

WEC::SSL - WEC::SSL frontent module

=head1 SYNOPSIS

 use WEC::SSL qw(openssl_version)

 my $version = openssl_version();
 print "Version string = '%s'\n", $version;
 print "Version number = %08X\n", $version;

=head1 DESCRIPTION

=head1 EXPORTS

=over 4

=item openssl_version

A dualvar scalar. Evaluates to a string with something like 
"OpenSSL 0.9.8 05 Jul 2005" in string context. Evaluates to a version number 
like 0x0090800f in numeric context.

Numeric version identifier work as follows:

 * MNNFFPPS: major minor fix patch status
 * The status nibble has one of the values 0 for development, 1 to e for betas
 * 1 to 14, and f for release.  The patch level is exactly that.
 * For example:
 * 0.9.3-dev	  0x00903000
 * 0.9.3-beta1	  0x00903001
 * 0.9.3-beta2-dev 0x00903002
 * 0.9.3-beta2    0x00903002 (same as ...beta2-dev)
 * 0.9.3	  0x0090300f
 * 0.9.3a	  0x0090301f
 * 0.9.4	  0x0090400f
 * 1.2.3z	  0x102031af

=back

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
