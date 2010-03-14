package WEC::SSL::EngineList;
use 5.006001;
use strict;
use warnings;

our $VERSION = "1.000";

# Cause XS load
require WEC::SSL::Engine;

use Exporter::Tidy other => [qw(all)];

1;
__END__

=head1 NAME

WEC::SSL::EngineList - iterate over openSSL engines

=head1 SYNOPSIS

  use WEC::SSL::EngineList;

  tie my %engines, 'WEC::SSL::EngineList';
  while (my ($name, $engine) = each %engines) {
    print "$name: $engine\n";
  }
  @engines    = WEC::SSL::EngineList->all;
  $nr_engines = WEC::SSL::EngineList->all;

=head1 DESCRIPTION

This module allows you to list the available openSSL engines. It implements a
tied hash interface. Doing the tie implicitely loads all engines.

=head1 METHODS

=item X<all>@engines = WEC::SSL::EngineList->all

This returns a list of all openSSL engines. The same result can be obtained by
using values in the tied interface, but this is more efficient. Implcitely loads
all engines.

=item $nr_engines = WEC::SSL::EngineList->all

Returns the number of openSSL engines.

=head1 EXPORT

None by default

The following methods can be exported:

=over 4

=item X<export_all>all
=back

=head1 SEE ALSO

L<WEC::SSL::Engine>

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL-EngineList@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
