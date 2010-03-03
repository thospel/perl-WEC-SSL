package WEC::SSL::Errors;
use 5.006001;
use strict;
use warnings;

our $VERSION = "1.000";

# Load XS prerequisites
require WEC::SSL::Utils;

1;
__END__

=head1 NAME

WEC::SSL::Errors - An OpenSSL error sequence

=head1 SYNOPSIS

  # A typical way to get to an SSL error sequemce:
  eval { do_crypto_stuff() };
  if ($@ && UNIVERSAL::isa($@, "WEC::SSL::Errors")) {
      # $@ is a complete error sequence

      # An array reference to the individual WEC::SSL::Error objects
      my $errors = $@->errors;

      # Where did the error occur (" at <file_name> line <line_number>.\n")
      my $where  = $@->where;
      # In which perl file
      my $file = $@->file;
      # On which line
      my $line = $@->line;

      printf "description = %s\n", $@->error_string;
      printf "code        = %d\n", $@->error_string;
      print "description = $@\n";
  }

=head1 DESCRIPTION

When you do a high level OpenSSL call, that one can in turn call several low
level functions. If an error happens in one of these this will probably cause
an error in a higher level which may in turn cause a problem in a yet higher
level until it comes back to the caller. OpenSSL will in such a case report
the whole sequence of errors. The WEC::SSL::Errors object represents such an
error sequence.

Whenever you call some crypto/ssl function through the WEC::SSL perl modules,
the exception that's raised can be such a WEC::SSL::Errors object. But not all
errors will be of this type. You can also get plain old string exceptions,
e.g. if the problem involves argument checking in before the real low level
call is done. Also, some of the low level calls don't report their errors 
through the OpenSSL error queue, and in that case you'll also get plain old 
string exceptions.

It has overloads so that it will call L<error_string|"error_string"> in a
string context (and always be true in a boolean context). These overloads are
available even if you didn't explicitely load WEC::SSL::Errors since you can
get error objects purely by using other parts of WEC::SSL. In particular this 
means that you can always use $@ as a string, and if the exception is uncaught
or rethrown you will get a sane string version of the error.

=head1 METHODS

=over 4

=item $errors->errors

Returns an array reference. Each element is one of the errors in the error 
sequence and of type L<WEC::SSL::Error|WEC::SSL::Error>. There will be always
at least one element in the array, and quite often in fact no more than one.

=item $errors->where

Returns the perl file and line number where the error happened in the normal
style that perl adds these to an exception, so of the form
" at <file_name> line <line_number>.\n". 
See L<WEC::SSL::Error::c_file|WEC::SSL::Error/c_file> and 
L<WEC::SSL::Error::c_line|WEC::SSL::Error/c_line> for the file and linenumber
in the source files of the OpenSSL library.

=item $errors->file

Returns the perl file where the error happened. See 
L<WEC::SSL::Error::c_file|WEC::SSL::Error/c_file> for the source file in the 
OpenSSL library.

=item $errors->line

Returns the perl line number where the error happened. See 
L<WEC::SSL::Error::c_line|WEC::SSL::Error/c_line> for the line in a source 
file in the OpenSSL library.

=item $errors->error_string

Returns a simple string description os the errors. It will consist of
the L<descriptions of the individual errors|WEC::SSL::Error/error_string>
separated by commas, followed by the perl file and line number.

In a numeric context the result will evaluate to the 
L<error code|WEC::SSL::Error/code> of the last error in the sequence.

=back

=head1 EXPORTS

None

=head1 EXAMPLE

  use WEC::SSL::BigInt;
  #line 28
  eval { WEC::SSL::BigInt::quotient(1, 0) };
  if ($@ && UNIVERSAL::isa($@, "WEC::SSL::Errors")) {
      # $@ is a complete error sequence
      my $errors = $@->errors;
      printf("There is %d error in the sequence\n", scalar @$errors);
      printf("Where = '%s'\n", $@->where);
      printf("File  = %s\n", $@->file);
      printf("Line  = %u\n", $@->line);
  
      printf "description = '%s'\n", $@->error_string;
      printf "code        = %d\n", $@->error_string;
      print "description  = '$@'\n";
  }

Which might output:

  There is 1 error in the sequence
  Where = ' at test.pl line 5.
  '
  File  = test.pl
  Line  = 28
  description = 'div by zero at test.pl line 28.
  '
  code        = 50770023
  description  = 'div by zero at test.pl line 28.
  '

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL-Errors@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
