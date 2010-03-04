package WEC::SSL::Engine;
use 5.006001;
use strict;
use warnings;

our $VERSION = "1.000";

# Load XS prerequisites
require WEC::SSL::Utils;

require XSLoader;
XSLoader::load('WEC::SSL::Engine', $VERSION);

use Exporter::Tidy
    other => [qw(taint
                 FLAGS_MALLOCED FLAGS_MANUAL_CMD_CTRL FLAGS_BY_ID_COPY
                 METHOD_RSA METHOD_DSA METHOD_DH METHOD_RAND METHOD_ECDH
                 METHOD_ECDSA METHOD_CIPHERS METHOD_DIGESTS METHOD_STORE
                 METHOD_ALL METHOD_NONE)];

1;
__END__

=head1 NAME

WEC::SSL::Engine - OpenSSL external cryptographic engine support

=head1 SYNOPSIS

  use WEC::SSL::Engine;

  $engine = WEC::SSL::Engine->by_name($name);

  $name = $engine->name;
  $desc = $engine->description;
  $flags       = $engine->flags;
  $old_flags   = $engine->flags($new_flags);

  $taint       = $engine->taint;
  $old_taint   = $engine->taint($new_taint);

=head1 DESCRIPTION

=head1 METHODS

=over 4

=item X<by_name>$engine = WEC::SSL::Engine->by_name($name)

Returns a reference to the engine called $name if $name is known. Raises
an exception otherwise.

The method is a wrapper for OpenSSL function L<ENGINE_by_id|ENGINE_by_id(3)>.
Notice that what OpenSSL calls an engine C<id> we call C<name>, and what
OpenSSL calls engine C<name> we call C<description>.

=item X<name>$name = $engine->name

Returns the name of the $engine.

This method is a wrapper for OpenSSL function L<ENGINE_get_id|ENGINE_get_id(3)>

=item X<description>$desc = $engine->description

Returns a string describing $engine.

This method is a wrapper for OpenSSL function L<ENGINE_get_name|ENGINE_get_name(3)>

An example could be:

  use WEC::SSL::Engine;
  my $engine = WEC::SSL::Engine->by_name("dynamic");

  # This should print "dynamic" again
  print $engine->name;

  # This might print something like "Dynamic engine loading support"
  print $engine->description;

=item X<flags>$flags = $engine->flags

Each engine has associated with it a set of flags you can query using this
method. It returns an integer that is a bitwise or of the flags that are
turned on.

A number of these flags may have symbolic names, see
L<FLAGS_MALLOCED|"FLAGS_MALLOCED">,
L<FLAGS_MANUAL_CMD_CTRL|"FLAGS_MANUAL_CMD_CTRL"> and
L<FLAGS_BY_ID_COPY|"FLAGS_BY_ID_COPY">.

This method is a wrapper for OpenSSL function
L<ENGINE_get_flags|ENGINE_get_flags(3)>.

=item $old_flags = $engine->flags($new_flags)

This sets a new value for the flags while returning the old value. You almost
certainly shouldn't be using this method (unless you are playing with engine
internals).

This method is a wrapper for OpenSSL functions
L<ENGINE_get_flags|ENGINE_get_flags(3)> and
L<ENGINE_set_flags|ENGINE_set_flags(3)>.

=item X<taint>$taint = $engine->taint

=item $old_taint = $engine->taint($new_taint);

A WEC::SSL::Engine object is in reality a reference to thingy with a special
meaning to the module internals. Its the taintedness of the thingy that
determines if the WEC::SSL::Engine is tainted, but naive use of the standard
L<Scalar::Util tainted method|Scalar::Util/tainted> method would test the
reference instead.

To avoid this confusion this method is a combination of a dereference and a
taint check of the thingy. It returns a true value if that is tainted, false
otherwise.

When called with an argument, it taints (if the argument is true) or untaints
(if the argument is false) both the reference and the thingy.

Trying to turn tainting off using a tainted argument will result in an
exception.

The method returns the old tainting state of the referenced argument.

Notice that with a $new_tainted argument this method changes taintedness
in place, also changing it for all aliases (but for them the reference
will not get tainted).

=item X<FLAGS_MALLOCED>FLAGS_MALLOCED

Not used anymore. It indicated if the C-level engine object was malloced or
not.

=item X<FLAGS_MANUAL_CMD_CTRL>FLAGS_MANUAL_CMD_CTRL

This flag is for ENGINEs that wish to handle the various command-related
control commands on their own. Without this flag, a default builtin function
C<ENGINE_ctrl()> handles these control commands on behalf of the ENGINE using
their C<"cmd_defns"> data.

=item X<FLAGS_BY_ID_COPY>FLAGS_BY_ID_COPY

This flag is for ENGINEs who return new duplicate structures when found via
C<"ENGINE_by_id()"> (which is always the case for engines you get by using the
perl interfaces only). When an ENGINE must store state (eg. if ENGINE_ctrl()
commands are called in sequence as part of some stateful process like
key-generation setup and execution), it can have this flag set. Then each
attempt to obtain the ENGINE will result in it being copied into a new
structure.

Normally, ENGINEs don't declare this flag so ENGINE_by_id() just increments
the existing ENGINE's structural reference count.

=back

=head1 EXPORT

Except for the constructors everything is exportable, but nothing is exported
by default. It uses L<Exporter::Tidy|Exporter::Tidy> for the exports, so
you can import methods under modified (prefixed) names.

=head1 SEE ALSO

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL-Engine@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
