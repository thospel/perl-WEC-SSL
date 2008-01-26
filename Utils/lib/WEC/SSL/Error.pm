package WEC::SSL::Error;
use 5.006001;
use strict;
use warnings;

our $VERSION = "0.01";

# Load XS prerequisites
require WEC::SSL::Utils;

use Exporter::Tidy
    library_ids => [qw(LIB_NONE LIB_SYS LIB_BN LIB_RSA LIB_DH LIB_EVP LIB_BUF
                       LIB_OBJ LIB_PEM LIB_DSA LIB_X509 LIB_ASN1 LIB_CONF
                       LIB_CRYPTO LIB_EC LIB_SSL LIB_BIO LIB_PKCS7 LIB_X509V3
                       LIB_PKCS12 LIB_RAND LIB_DSO LIB_ENGINE LIB_OCSP LIB_UI
                       LIB_COMP LIB_ECDSA LIB_ECDH LIB_STORE)];

1;
__END__

=head1 NAME

WEC::SSL::Error - A single error in an OpenSSL error sequence

=head1 SYNOPSIS

  # A typical way to get to an SSL error:
  eval { do_crypto_stuff() };
  if ($@ && UNIVERSAL::isa($@, "WEC::SSL::Errors")) {
      # $@ is a complete error sequence
      my $errors = $@->errors;
      for my $error (@$errors) {
          # $error is a WEC::SSL::Error object
          # representing one error in a sequence
          printf "code       = %s\n", $error->code;
          printf "reason     = %s\n", $error->reason;       # as string
          printf "reason     = %d\n", $error->reason;       # as number
          printf "data       = %s\n", $error->data || "(none)";
          printf "c_library  = %s\n", $error->c_library;    # as string
          printf "c_library  = %d\n", $error->c_library;    # as number
          printf "c_function = %s\n", $error->c_function;   # as string
          printf "c_function = %d\n", $error->c_function;   # as number
          printf "c_file     = %s\n", $error->c_file;
          printf "c_line     = %s\n", $error->c_line;

          printf "description = %s\n", $error->error_string;
          printf "code        = %d\n", $error->error_string;
          print "description = $error\n";
      }
  }

=head1 DESCRIPTION

A WEC::SSL::Error object represents one element in an ssl/crypto error
sequence (L<WEC::SSL::Errors>).

It has overloads so that it will call
L<error_string|"error_string"> in a string context and L<code|"code"> in a
numeric context (and always be true in a boolean context). These overloads are
available even if you didn't explicitely load WEC::SSL::Error since you can get
error objects purely by using other parts of WEC::SSL.

=head1 METHODS

=over 4

=item $error->code

Returns a numeric representing the current error. In reality this
number is constructed from several parts which can be accessed with
L<reason|"reason">, L<c_function|"c_function"> and L<c_library|"c_library">.
The error code is guaranteed to be an integer in the range [1, 2**32-1].

=item $error->data

Optional extra data associated with this error. Returns undef if there is none.

=item $error->reason

Returns a dualvar that is a simple reason description in string context
and a number representing this reason in numeric context. The reason is
only guaranteed unique within a given L<c_function|"c_function"> and
L<c_library|"c_library">

=item $error->c_function

Returns a dualvar that in string context is the name of the internal c
function in which the error occured. In numeric context it's an identifier
representing this function. The C function is only guaranteed to be
unique within a given L<c_library|"c_library">.

=item $error->c_library

Returns a dualvar that in string context is the name of the internal c
library in which the error occured. In numeric context it's an identifier
representing this library. The C library is guaranteed unique.

=item $error->c_file

Returns the name of the C source file where the error occured. To know where
in your perl code an error occured, see
L<WEC::SSL::Errors::where|WEC::SSL::Errors/where>.

=item $error->c_line

Returns the line in the C source file where the error occured. To know where
in your perl code an error occured, see
L<WEC::SSL::Errors::where|WEC::SSL::Errors/where>.

=item $error->error_string;

Return a dualvar that in string context is a simple description of the
current error, and the error code in numeric context.

=back

=head1 EXPORTS

=over 4

=item LIB_NONE LIB_SYS LIB_BN LIB_RSA LIB_DH LIB_EVP LIB_BUF LIB_OBJ LIB_PEM LIB_DSA LIB_X509 LIB_ASN1 LIB_CONF LIB_CRYPTO LIB_EC LIB_SSL LIB_BIO LIB_PKCS7 LIB_X509V3 LIB_PKCS12 LIB_RAND LIB_DSO LIB_ENGINE LIB_OCSP LIB_UI LIB_COMP LIB_ECDSA LIB_ECDH LIB_STORE

Constants for the crypto/ssl libraries. They will correspond to the numerical
values returned by the L<c_library|"c_library"> method.

=back

=head1 EXAMPLE

  use WEC::SSL::BigInt;

  eval { WEC::SSL::BigInt::quotient(1, 0) };
  if ($@ && UNIVERSAL::isa($@, "WEC::SSL::Errors")) {
      # $@ is a complete error sequence
      my $errors = $@->errors;
      for my $error (@$errors) {
          # $error is a WEC::SSL::Error object
          # representing one error in a sequence
          printf "code       = %08X\n", $error->code;
          printf "reason     = %s\n",   $error->reason;
          printf "reason     = %03X\n", $error->reason;
          printf "data       = %s\n",   $error->data || "(none)";
          printf "c_library  = %s\n",   $error->c_library;
          printf "c_library  = %02X\n", $error->c_library;
          printf "c_function = %s\n",   $error->c_function;
          printf "c_function = %03X\n", $error->c_function;
          printf "c_file     = %s\n",   $error->c_file;
          printf "c_line     = %s\n",   $error->c_line;

          printf "description = %s\n",   $error->error_string;
          printf "description = %08X\n", $error->error_string;
          print "description = $error\n";
      }
  }

Might output:

  code       = 0306B067
  reason     = div by zero
  reason     = 067
  data       = (none)
  c_library  = bignum routines
  c_library  = 03
  c_function = BN_div
  c_function = 06B
  c_file     = bn_div.c
  c_line     = 197
  description = div by zero
  description = 0306B067
  description = div by zero

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL-Error@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
