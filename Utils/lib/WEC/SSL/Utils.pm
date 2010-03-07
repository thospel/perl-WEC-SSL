package WEC::SSL::Utils;
use 5.006001;
use strict;
use warnings;

our $VERSION = "1.000";

require XSLoader;
XSLoader::load('WEC::SSL::Utils', $VERSION);

use Exporter::Tidy
    other => [qw(taint fchmod)];

package WEC::SSL::Errors;
# Declare here instead of in Errors.pm since we *always* want these overloads
use overload
    "!"		=> \&WEC::SSL::Utils::_false,
    "bool"	=> \&WEC::SSL::Utils::_true,
    "0+"	=> \&WEC::SSL::Utils::_refaddr,
    '""'	=> \&error_string;

package WEC::SSL::Error;
# Declare here instead of in Error.pm since we *always* want these overloads
use overload
    "!"		=> \&WEC::SSL::Utils::_false,
    "bool"	=> \&WEC::SSL::Utils::_true,
    "0+"	=> \&code,
    '""'	=> \&error_string;

1;
__END__

=head1 NAME

WEC::SSL::Utils - Load the WEC::SSL dynamic library

=head1 SYNOPSIS

  use WEC::SSL::Utils;

  # The following lines assume the used functions have been imported.
  # Otherwise write things like tainted as WEC::SSL::Utils::tainted
  $tainted = tainted($arg);
  $old_tainted = tainted($arg, $new_tainted);

=head1 DESCRIPTION

This is an internal module for WEC::SSL which simply loads the needed OpenSSL
dynamic libraries and does some initialization. This is executed as needed by
the other modules and so should not normally be needed to be done by the user.

=head1 METHODS

=over 4

=item X<tainted>$tainted = tainted($arg)

=item $old_tainted = tainted($arg, $new_tainted)

When called with two arguments, it taints (if the second argument is true) or 
untaints (if the second argument is false) the first argument.

Trying to turn tainting off using a tainted second argument will result in an
exception.

The method returns the old tainting state of the first argument.

See also L<Scalar::Utils::tainted|Scalar::Utils/tainted>.

=back

=head1 EXPORTS

Nothing is exported by default.

L<tainted|"tainted"> is exportable.

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL-Utils@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
