package WEC::SSL::Reciprocal;
use 5.006001;
use strict;
use warnings;

our $VERSION = "1.000";

require WEC::SSL::BigInt;

use Exporter::Tidy
    other => [qw(sensitive tainted mod_multiply divide quotient remainder)];

1;
__END__

=head1 NAME

WEC::SSL::Reciprocal - Repeated WEC::SSL::BigInt operations with the same divisor.

=head1 SYNOPSIS

  $recp = WEC::SSL::Reciprocal->new($divisor);

  # Sensitivity and taintedness
  $sensitive = $recp->sensitive;
  $old_sensitive = $recp->sensitive($new_sensitive);
  $tainted = $recp->tainted;
  $old_tainted = $recp->tainted($new_tainted);

  $rest = $recp->mod_multiply($a, $b);
  $quotient = $recp->divide($a);
  ($quotient, $remainder) = $recp->divide($a);
  $quotient = $recp->quotient($a);
  $remainder = $recp->remainder($a);

=head1 DESCRIPTION


=head1 METHODS

=over 4

=item X<new>$recp = WEC::SSL::Reciprocal->new($divisor)

Returns a new WEC::SSL::Reciprocal object based on $divisor. You can use this
to do repeated division/remainder operations with $divisor as divisor.

The result inherits sensitivity and taintedness from $divisor.

Raises an exception in case $divisor is 0.

=item X<sensitive>$sensitive = $recp->sensitive

=item $old_sensitive = $recp->sensitive($new_sensitive)

Every WEC::SSL::Reciprocal object has an associated sensitivity flag. When
called without argument the sensitive method returns a true value if this
flag is set, false otherwise. When called with an argument it makes the target
object sensitive if this value is true, non-sensitive otherwise. The
old sensitivity before the change is still returned.

Trying to turn sensitivity off using a sensitive (false) value will raise an
exception.

Notice that with a $new_sensitive argument this method changes sensitivity
in place, also changing it for all aliases.

Taintedness of $new_sensitive may or may not propagate to $recp.

When a new WEC::SSL::BigInt object is created using one of the methods
supported by this object, its sensitivity flag will depend on the
sensitivity of the object and all arguments of the operation. The result will
be sensitive if the object or any of the arguments is sensitive, non-sensitive
otherwise. Pure perl values count as non-sensitive. So sensitivity propagation
works in essentially the same way as taint propagation.

The sensitivity flag is used whenever a WEC::SSL::Reciprocal object is
destroyed. If at that point the flag is set, the old value is cleared from
memory by overwriting its internal storage with zeros before freeing the
memory.

The idea is that you set the sensitivity flags at the moment you store
a sensitive key into a variable, so that after that point you don't have to
worry what exactly happens to this key or the operations done on it, since
all derived values will also be sensitive and all of them will be zeroed when
they go out of scope. In particular, a newly created WEC::SSL::Reciprocal
object will inherit the sensitity of the argument it is the reciprocal of.

=item X<tainted>$tainted = $recp->tainted

=item $old_tainted = $recp->tainted($new_tainted)

A WEC::SSL::Reciprocal object is typically passed around as a reference to a
perl integer which in turn represents the address of a C object. Its the
taintedness of the perl integer that determines if the WEC::SSL::Reciprocal is
tainted, but naive use of the standard
L<Scalar::Util tainted method|Scalar::Util/tainted> method would test the
reference instead.

To avoid this confusion this method is a combination of the dereference and
taint check of the perl integer. It returns a true value if that is tainted,
false otherwise.

When called with an argument, it taints (if the argument is true) or untaints
(if the argument is false) both the reference and the referenced perl integer.

Trying to turn tainting off using a tainted argument will result in an
exception.

Notice that with a $new_tainted argument this method changes taintedness
in place, also changing it for all aliases (but for them the reference
will not get tainted).

Sensitivity of the argument may or may not propagate to the
WEC::SSL::Reciprocal object.

=item X<mod_multiply>$rest = $recp->mod_multiply($a, $b)

If

  $recp = WEC::SSL::Reciprocal->new($divisor)

then this is essentially equivalent to:

  $rest = remainder($a * $b, $divisor)

               $a   $b $divisor $rest
  mod_multiply(-12, 1, -7)    = -5
  mod_multiply(-12, 1,  7)    = -5
  mod_multiply( 12, 1, -7)    =  5
  mod_multiply( 12, 1,  7)    =  5

Notice the different sign rules compared to
L<WEC::SSL::BigInt::mod_multiply|WEC::SSL::BigInt/mod_multiply> which is based
on L<WEC::SSL::BigInt::abs_remainder|WEC::SSL::BigInt/abs_remainder> instead
of WEC::SSL::BigInt::remainder|WEC::SSL::BigInt/remainder>.

This method is a wrapper for OpenSSL function
L<BN_mod_mul_reciprocal|BN_mod_mul_reciprocal(3)>.

=item X<divide>$quotient = $recp->divide($a)

If

  $recp = WEC::SSL::Reciprocal->new($divisor)

then this is essentially equivalent to:

  $quotient = int($a / $divisor)

         $a   $divisor $quotient
  divide(-12, -7)    =  1
  divide(-12,  7)    = -1
  divide( 12, -7)    = -1
  divide( 12,  7)    =  1

This method is a wrapper for OpenSSL function L<BN_div_recp|BN_div_recp(3)>.

=item ($quotient, $remainder) = $recp->divide($a)

If

  $recp = WEC::SSL::Reciprocal->new($divisor)

then this is essentially equivalent to:

  $quotient  = int($a / $divisor)
  $remainder = $a - $quotient * $divisor
 or
  $remainder = $a->remainder($divisor);

         $a   $divisor $quotient $remainder
  divide(-12, -7)    =  1        -5
  divide(-12,  7)    = -1        -5
  divide( 12, -7)    = -1         5
  divide( 12,  7)    =  1         5

This method is a wrapper for OpenSSL function L<BN_div_recp|BN_div_recp(3)>.

=item X<quotient>$quotient = $recp->quotient($a)

If

  $recp = WEC::SSL::Reciprocal->new($divisor)

then this is essentially equivalent to:

  $quotient = int($a / $divisor)

           $a   $divisor $quotient
  quotient(-12, -7)    =  1
  quotient(-12,  7)    = -1
  quotient( 12, -7)    = -1
  quotient( 12,  7)    =  1

This method is a wrapper for OpenSSL function L<BN_div_recp|BN_div_recp(3)>.

=item X<remainder>$remainder = $recp->remainder($a)

If

  $recp = WEC::SSL::Reciprocal->new($divisor)

then this is essentially equivalent to:

  $remainder = $a->remainder($divisor)

            $a   $divisor $remainder
  remainder(-12, -7)    = -5
  remainder(-12,  7)    = -5
  remainder( 12, -7)    =  5
  remainder( 12,  7)    =  5

This method is a wrapper for OpenSSL function L<BN_div_recp|BN_div_recp(3)>.

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

Ton Hospel, E<lt>WEC-SSL-Reciprocal@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
