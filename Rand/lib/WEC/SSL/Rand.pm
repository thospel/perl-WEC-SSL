package WEC::SSL::Rand;
use 5.006001;
use strict;
use warnings;
use Carp;
use POSIX  qw(O_WRONLY O_CREAT O_EXCL ENOENT EEXIST EINTR);
use Socket qw(AF_UNIX SOCK_STREAM pack_sockaddr_un);
use Fcntl  qw(S_IMODE);

our $VERSION = "1.000";

# Load XS prerequisites
use WEC::SSL::Utils qw(tainted fchmod);

require XSLoader;
XSLoader::load('WEC::SSL::Rand', $VERSION);

use Exporter::Tidy
    other => [qw(seed seed_canonical status
                 bytes pseudo_bytes string pseudo_string
                 try_load_file try_write_file load_file store_file write_file
                 filename try_load_from_egd load_from_egd try_fetch_from_egd 
                 fetch_from_egd egd_entropy RAND_DATA)];

use constant {
    READ_BLOCK	=> 2**14,
};

sub load_file {
    my ($filename, $left) = @_;

    $left = 9**9**9 if !defined $left;
    $left = int $left;
    croak "max_bytes $left is negative" if $left < 0;

    open(my $fh, "<", $filename) || croak "Could not open '$filename': $!";
    binmode $fh;
    # Taint propagation
    my $read = 0 + substr("0$left", 0, 1);
    while ($left) {
        my $rc = read($fh, my $buffer,
                      $left > READ_BLOCK() ? READ_BLOCK : $left);
        croak "Error reading '$filename': $!" if !defined $rc;
        # Taint propagation
        $read += substr("0$buffer", 0, 1) if !$read;
        last if $rc == 0;
        tainted($buffer, 0);
        seed($buffer);
        $read += $rc;
        $left -= $rc;
    }
    close($fh) || croak "Error closing '$filename': $!";
    return $read;
}

sub store_file {
    my ($filename) = @_;

    if (lstat($filename)) {
        croak "Path '$filename' exists but is not a regular file" if ! -f _;
    } else {
        croak "Could not lstat '$filename': $!" if $! != ENOENT;
    }

    # Only load these if needed
    require File::Spec;
    require File::Temp;

    my ($volume, $directories) = File::Spec->splitpath($filename);
    my $dir = File::Spec->catpath($volume, $directories, "") .  substr($filename, 0, 0);
    my ($fh, $new) = File::Temp::tempfile(DIR => $dir);
    binmode $fh;	# tempfile already does this, but is undocumented
    eval {
        local $\;
        my $bytes = bytes(RAND_DATA());
        print($fh $bytes) || croak "Error writing to '$new': $!";
        close($fh) || croak "Error closing '$new': $!";
        rename($new, $filename) ||
            die "Could not rename '$new' to '$filename': $!";
    };
    if ($@) {
        $fh = undef;
        unlink($new) || die "Could not unlink '$new': $! after $@";
        die $@;
    }
    return status() ? RAND_DATA() : undef;
}

sub write_file {
    my ($filename, $perms) = @_;
    $perms = 0600 unless defined $perms;
    croak "Invalid permissions" if S_IMODE($perms) != $perms;
    sysopen(my $fh, $filename, O_WRONLY | O_CREAT, $perms) ||
        croak "Could not create '$filename': $!";
    my $mode = $perms & ~umask();
    my @stat = stat($fh) or
        die "Assert: Can't stat open handle to '$filename': $!";
    my $have_mode = S_IMODE($stat[2]);
    if (-f _) {
        if ($mode != $have_mode) {
            fchmod(fileno($fh), $mode) ||
                croak "Could not fchmod '$filename': $!";
        }
        my $old_fh = select($fh);
        $| = 1;
        select($old_fh);
    }
    binmode $fh;
    my $bytes = bytes(RAND_DATA());
    local $\;
    print($fh $bytes) || croak "Error writing to '$filename': $!";
    if (-f _) {
        truncate($fh, length $bytes) ||
            croak "Could not truncate '$filename': $!";
    }
    close($fh) || croak "Error closing '$filename': $!";
    return status() ? RAND_DATA() : undef;
}

sub load_from_egd {
    my ($pathname, $nr_bytes) = @_;
    $nr_bytes = defined $nr_bytes ? int $nr_bytes : 255;
    croak "nr_bytes $nr_bytes is negative" if $nr_bytes < 0;
    croak "nr_bytes $nr_bytes is out of range" if $nr_bytes > ~0;
    socket(my $s, AF_UNIX, SOCK_STREAM, 0) ||
        croak "Could not an unix socket: $!";
    until (connect($s, pack_sockaddr_un($pathname))) {
        # OpenSSL has a lot more non-error errno's here. I don't buy them.
        croak "Could not connect to '$pathname': $!" if $! != EINTR;
    }
    my $gotten = $nr_bytes-$nr_bytes;	# 0 with the taint of $nr_bytes
    while ($gotten < $nr_bytes) {
        my $wanted = $nr_bytes - $gotten;
        $wanted = 255 if $wanted > 255;
        my $command = pack("CC", 1, $wanted);
        while ($command ne "") {
            my $rc = syswrite($s, $command);
            croak "Error writing to '$pathname': $!" if !defined $rc;
            substr($command, 0, $rc) = "";
        }
        defined(my $rc = sysread($s, my $nr, 1)) ||
            croak "Error reading from '$pathname': $!";
        croak "Unexpected EOF from '$pathname'" if $rc == 0;
        $nr =~ /(.)/s || die "Assertion: length one string doesn't match .";
        $nr = unpack("C", $1);
        my $buffer;
        my $got = 0;
        while ($nr) {
            my $rc = sysread($s, $buffer, $nr, $got);
            if (!$rc) {
                tainted($buffer, 0);
                seed($buffer) if $got;
                croak "Error reading from '$pathname': $!" if !defined $rc;
                croak "Unexpected EOF from '$pathname'";
            }
            $got += $rc;
            $nr  -= $rc;
        }
        tainted($buffer, 0);
        seed($buffer) if $got;
        $gotten += $got;
        last if $got < $wanted;
    }
    return $gotten;
}

sub fetch_from_egd {
    my ($pathname, $nr_bytes) = @_;
    $nr_bytes = defined $nr_bytes ? int $nr_bytes : 255;
    croak "nr_bytes $nr_bytes is negative" if $nr_bytes < 0;
    croak "nr_bytes $nr_bytes is out of range" if $nr_bytes > ~0;
    socket(my $s, AF_UNIX, SOCK_STREAM, 0) ||
        croak "Could not an unix socket: $!";
    until (connect($s, pack_sockaddr_un($pathname))) {
        # OpenSSL has a lot more non-error errno's here. I don't buy them.
        croak "Could not connect to '$pathname': $!" if $! != EINTR;
    }
    my $gotten = 0;
    my $result = "";
    while ($gotten < $nr_bytes) {
        my $wanted = $nr_bytes - $gotten;
        $wanted = 255 if $wanted > 255;
        my $command = pack("CC", 1, $wanted);
        while ($command ne "") {
            my $rc = syswrite($s, $command);
            croak "Error writing to '$pathname': $!" if !defined $rc;
            substr($command, 0, $rc) = "";
        }
        defined(my $rc = sysread($s, my $nr, 1)) ||
            croak "Error reading from '$pathname': $!";
        croak "Unexpected EOF from '$pathname'" if $rc == 0;
        $nr =~ /(.)/s || die "Assertion: length one string doesn't match .";
        $nr = unpack("C", $1);
        my $got = 0;
        while ($got < $nr) {
            my $rc = sysread($s, $result, $nr-$got, $gotten);
            if (!$rc) {
                tainted($result, 0);
                seed($result) if $gotten;
                croak "Error reading from '$pathname': $!" if !defined $rc;
                croak "Unexpected EOF from '$pathname'";
            }
            $got    += $rc;
            $gotten += $rc;
        }
        last if $got < $wanted;
    }
    tainted($result, 0);
    seed($result);
    tainted($result, 1) if tainted($nr_bytes);
    return $result;
}

sub egd_entropy {
    my ($pathname) = @_;
    socket(my $s, AF_UNIX, SOCK_STREAM, 0) ||
        croak "Could not an unix socket: $!";
    my $path_tainted = tainted($pathname, 0);
    until (connect($s, pack_sockaddr_un($pathname))) {
        # OpenSSL has a lot more non-error errno's here. I don't buy them.
        croak "Could not connect to '$pathname': $!" if $! != EINTR;
    }
    my $command = pack("C", 0);
    defined(my $rc = syswrite($s, $command)) ||
        croak "Error writing to '$pathname': $!";
    croak "Unexpected EOF from '$pathname'" if $rc == 0;
    my $nr = 4;
    my $buffer = "";
    while ($nr) {
        my $rc = sysread($s, $buffer, $nr, length $buffer);
        if (!$rc) {
            croak "Error reading from '$pathname': $!" if !defined $rc;
            croak "Unexpected EOF from '$pathname'";
        }
        $nr  -= $rc;
    }
    my $entropy = unpack("N", $buffer) / 8;
    tainted($entropy, $path_tainted);
    return $entropy;
}

1;
__END__

=head1 NAME

WEC::SSL::Rand - OpenSSL PRNG operations

=head1 SYNOPSIS

  use WEC::SSL::Utils;

  # The following lines assume the used functions have been imported.
  # Otherwise write things like tainted as WEC::SSL::Rand::tainted

  # Seeding the PRNG
  seed($bytes, $entropy);
  seed($bytes);
  seed_canonical($bytes, $entropy);
  seed_canonical($bytes);
  $bool = status();

  # Generating random byte sequences
  $bytes = bytes($nr_bytes);
  $bytes = pseudo_bytes($nr_bytes);
  $bytes = string($pattern, $nr_chars);
  $bytes = string($pattern);
  $bytes = pseudo_string($pattern, $nr_chars);
  $bytes = pseudo_string($pattern);

  # Loading and saving PRNG state
  $filename = filename();
  $read = try_load_file($filename, $max_bytes);
  $read = try_load_file($filename);
  $read = load_file($filename, $max_bytes);
  $read = load_file($filename);
  $written = try_write_file($filename);
  $written = write_file($filename, $perms);
  $written = write_file($filename);
  $written = store_file($filename);

  # Talking to EGD (entropy gathering daemon)
  $read = try_load_from_egd($pathname, $nr_bytes);
  $read = try_load_from_egd($pathname);
  $bytes = try_fetch_from_egd($pathname, $nr_bytes);
  $bytes = try_fetch_from_egd($pathname);
  $bytes = egd_entropy($pathname);

  # Constants
  $length = RAND_DATA();

=head1 DESCRIPTION


=head1 METHODS

=over 4

=item X<seed> seed($bytes, $entropy)

Mixes $bytes into the PRNG state. Thus, if the data in $bytes are unpredictable
to an adversary, this increases the uncertainty about the state and makes the
PRNG output less predictable.

The entropy argument is (the lower bound of) an estimate of how much randomness
is contained in $bytes, measured in bytes. Details about sources of randomness
and how to estimate their entropy can be found in the literature, e.g.
RFC 1750.

An exception is raised if the entropy argument is negative or greater than the 
byte-length of $bytes. This test may not be strict enough though in case 
$bytes is an upgraded string internally.

An exception is also raised if $entropy or $bytes is tainted while $entropy
is non-zero.

This function is a wrapper for OpenSSL function L<RAND_add|RAND_add(3)>

=item seed($bytes)

This is the same as the version with an $entropy argument, but all bytes
are assumed to be completely random, so

  $entropy = length $bytes

$bytes must now be a real byte sequence though (no characters with a code
of 256 or above) because otherwise the byte-length is badly defined
(it will raise an exception in that case).

This function is a wrapper for OpenSSL function L<RAND_seed|RAND_seed(3)>

=item X<seed_canonical> seed_canonical($bytes, $entropy)

This is the same as L<seed|"seed">, except that $bytes is first brought into
a canonical form internally (pure bytes if $bytes has no charachters with a
code greater or equal to 256, and UTF8 encoded otherwise).

Normally you wouldn't care since all you're interested in is that all the
entropy gets stirred into the PRNG, and it doesn't matter what encoding that
entropy has. But you might care if you're trying to exactly reproduce a given
PRNG state.

This function is a wrapper for OpenSSL function L<RAND_add|RAND_add(3)>

=item seed_canonical($bytes)

This is really the same as L<seed|"seed"> since the pure byte form of the
$bytes argument is implicitely canonical.

This function is a wrapper for OpenSSL function L<RAND_seed|RAND_seed(3)>

=item X<status>$bool = status()

Returns true if the PRNG has been seeded with enough data, false otherwise.

This method is a wrapper for OpenSSL function L<RAND_status|RAND_status(3)>.

=item X<bytes>$bytes = bytes($nr_bytes)

Returns a string of $nr_bytes cryptographically strong pseudo-random bytes.
An error occurs if the PRNG has not been seeded with enough randomness to
ensure an unpredictable byte sequence.

This method is a wrapper for OpenSSL function L<RAND_bytes|RAND_bytes(3)>.

=item X<pseudo_bytes>$bytes = pseudo_bytes($nr_bytes)

Returns a string of $nr_bytes strong pseudo-random bytes. They can be used for
non-cryptographic purposes and for certain purposes in cryptographic protocols,
but usually not for key generation etc.

The returned result is always tainted if the PRNG is not sufficiently seeded
(see L<status|"status">).

This method is a wrapper for OpenSSL function
L<RAND_pseudo_bytes|RAND_pseudo_bytes(3)>.

=item X<string>$bytes = string($pattern, $nr_chars)

=item $bytes = string($pattern)

Returns a string of length $nr_chars (defaults to 1 if omitted) with characters
chosen from a bag determined by $pattern. $pattern is the sequence of allowed
characters, where it's also allowed to use ranges.

The maximum number of characters that may be specified by a pattern depends on
perl internals details, but should be at least 10**12 (if you use ranges).

Examples:

  # Return a length 16 string made up of a random sequence of "0" and "1"
  $string = string('01', 16);

  # Return a length 8 string made up of a random sequence of uppercase letters
  $string = string('A-Z', 8);

If a character appears multiple times in a sequence, it's that much more
likely to get selected.

  # Return a length 15 string made up of a random sequence of "0" and "1"
  # On average there will be 10 zeros and 5 ones.
  $string = string('010', 15);

If any of the characters in the range has a numeric value of 256 or greater,
the returned string will be in upgraded form, even if none of the characters
in the result has a numeric value of 256 or higher.

A C<\> can be used to escape any non-alpha-numeric character (in particular
C<\\> itself and C<-> to indicate a literal -, not a range). Escapes for a
number of alphanumeric characters are also regognized.

The random character selection is cryptographically strong.
An error occurs if the PRNG has not been seeded with enough randomness to
ensure an unpredictable byte sequence.

This function is uses OpenSSL function L<RAND_bytes|RAND_bytes(3)>.

=item X<pseudo_bytes>$bytes = pseudo_string($pattern, $nr_chars)
=item $bytes = pseudo_string($pattern)

The same as L<string|"string"> except that the selection of characters is
not necessarily unpredicatble and not having enough entropy is not fatal.
(But the resulting string will be tainted in that case).

This method is uses OpenSSL function L<RAND_pseudo_bytes|RAND_pseudo_bytes(3)>.

=item X<filename>$filename = filename()

OpenSSL programs often use a file from which it loads an
initial random state at program start and saves back the (changed) random
state at program end.

This method returns the name of this file (for the currently running user).
Usually this will be a per user file, but on some systems it can also be
something like F</dev/arandom>.

The returned name can be overridden using the environment variable
C<RANDFILE> (if the program is running as the user himself). To determine
the per user filename, the environment variable C<HOME> may be used.

  # This might e.g. print /home/user/.rnd
  print filename();

This function is a wrapper for OpenSSL function
L<RAND_file_name|RAND_file_name(3)>.

=item X<try_load_file>$read = try_load_file($filename, $max_bytes)

=item $read = try_load_file($filename)

This function attempts to read upto $max_bytes bytes from file $filename and
add them to the PRNG (with entropy zero). If $max_bytes is not given, the
complete file is read. However, in that last case the read may be broken off
after 2048 bytes if the file is really a device (depending on OpenSSL
compilation details).

It returns the number of bytes actually read. I/O failures will not raise an
exception but simply return 0. Notice that the file gets opened in binmode.
The returned value is always tainted in a perl where tainting is on.

This function is a wrapper for OpenSSL function
L<RAND_load_file|RAND_load_file(3)>.

=item X<load_file>$read = load_file($filename)

=item $read = load_file($filename, $nr_bytes)

This function is like L<try_load_file|"try_load_file">, but always raises an
exception for all errors.

It attempts to read upto $max_bytes bytes from file $filename and add them to
the PRNG (with entropy zero). If $max_bytes is not given, the complete file is
read. The behaviour of this function without $max_bytes on special files is
unspecified.

=item X<try_write_file>$written = try_write_file($filename)

Writes a number of random bytes (L<RAND_DATA|"RAND_DATA">) to file $filename
which can then later be used to initialize the PRNG by calling
L<try_load_file|"try_load_file"> or L<load_file|"load_file">.

If $filename doesn't exist yet, it gets created with mode 0600 (modified by
umask). Otherwise it's opened (with truncation). In either case it's then
immediately L<chmodded|chmod(2)> to mode 0600 (not modified by the umask).

If the bytes were generated from an insufficiently seeded PRNG undef is
returned. Otherwise the number of bytes actually written is returned. A
returncode of 0 implies some sort of I/O error. If $filename is a device, no
file I/O may get done while a fake value of 1 gets returned (whatever the state
of the PRNG). The assumption is that the write and chmod may cause problems
otherwise.

This function is a wrapper for OpenSSL function
L<RAND_write_file|RAND_write_file(3)>.

=item X<write_file>$written = write_file($filename)

=item $written = write_file($filename, $perms)

Writes a number of random bytes (L<RAND_DATA|"RAND_DATA">) to file $filename
which can then later be used to initialize the PRNG by calling
L<try_load_file|"try_load_file"> or L<load_file|"load_file">.

If $filename doesn't exist yet, it gets created with mode $perms (defaults to
0600, in either case it still gets modified by the current umask). Otherwise
it's opened (without truncation). In either case the open handle is checked for
being a regular file, and if so its mode is checked against the expectation.
If not as expected an fchmod is done.

So there is no protection against trying to write to a character or block
device, but the mode change is only done on regular files.

Then the random bytes get written, after which the file gets truncated just
after them (but only if the file is a regular file).

Any error except insufficient entropy will raise an exception.
In case of sufficient entropy the number of bytes written (this will be
L<RAND_DATA|"RAND_DATA">) is returned. In the case of insufficient entropy
undef will be returned. So if the function returns without raising an
exception you can be sure L<RAND_DATA|"RAND_DATA"> bytes got written, and you
can simply use the returncode as boolean that indicates if the stored bytes
are sufficiently random.

  # Write random state to the default user file
  write_file(filename());

This function is uses OpenSSL function L<RAND_bytes|RAND_bytes(3)>.

=item X<store_file>$written = store_file($filename)

Securely (using L<File::Temp|File::Temp>) a temporary file in the same
directory as $filename, writes a number of random bytes
(L<RAND_DATA|"RAND_DATA">) to it and then renames the temporary file over
$filename. Later this file can then for example be used to initialize the PRNG
by calling L<try_load_file|"try_load_file"> or L<load_file|"load_file">.

Before doing all this $filename is checked with an lstat. If the file exists
but isn't a regular file an exception is thrown. This will avoid accidentally
overwritig a special file (like /dev/random), but of course there is a time
period between this test and the final rename that the situation can have
changed. Unfortunately this race conditions is unavoidable, but it shouldn't
matter in most usage scenarios. Decide for yourself though!

Any error except insufficient entropy will raise an exception (and will clean
up the temporary file). In case of sufficient entropy the number of bytes
written (this will be L<RAND_DATA|"RAND_DATA">) is returned. In the case of
insufficient entropy undef will be returned. So if the function returns
without raising an  exception you can be sure L<RAND_DATA|"RAND_DATA"> bytes
got written, and you can simply use the returncode as boolean that indicates if
the stored bytes are sufficiently random.

This function is uses OpenSSL function L<RAND_bytes|RAND_bytes(3)>.

=item X<try_load_from_egd>$read = try_load_from_egd($pathname, $nr_bytes)

=item $read = try_load_from_egd($pathname)

This function tries to fetch $nr_bytes bytes (defaults to 255 if not given)
from EGD socket $pathname and then adds them to the PRNG entropy pool with
entropy equal to the number of bytes. Throws an exception if $pathname is
tainted (otherwise you could end up with an incorrectly accounted entropy
pool).

It returns the number of bytes that were gotten from EGD and stirred into the
entropy pool. This number can be 0 if there's no entropy available from
EGD, but also if $pathname isn't a UNIX socket (that's a bug in OpenSSL 0.9.8).

Will raise an exception in case of an I/O error.

This function is a wrapper for OpenSSL function
L<RAND_egd_bytes|RAND_egd_bytes(3)>.

=item X<try_fetch_from_egd>$bytes = try_fetch_from_egd($pathname, $nr_bytes)

=item $bytes = try_fetch_from_egd($pathname)

This function tries to fetch $nr_bytes bytes (defaults to 255 if not given)
from EGD socket $pathname and then adds them to the PRNG entropy pool with
entropy equal to the number of bytes. Throws an exception if $pathname is
tainted (otherwise you could end up with an incorrectly accounted entropy
pool).

It returns the string of bytes that were gotten from EGD and stirred into the
entropy pool. This string can be empty if there's no entropy available from
EGD, but also if $pathname isn't a UNIX socket (that's a bug in OpenSSL 0.9.8).

Will raise an exception in case of an I/O error.

This function is a wrapper for OpenSSL function
L<RAND_egd_query_bytes|RAND_egd_query_bytes(3)>.

=item $bytes = egd_entropy($pathname);

Returns the entropy available in $pathname measured in bytes. The result 
can be fractional (EGD measures its entropy in bits).

=item X<RAND_DATA>$length = RAND_DATA()

This returns a constant value indicating how many bytes the functions
L<try_write_file|"try_write_file">, L<write_file|"write_file"> and
L<store_file|"store_file"> will try to write.

=back

=head1 EXPORT

Everything is exportable, but nothing is exported by default. It uses
L<Exporter::Tidy|Exporter::Tidy> for the exports, so you can import methods
under modified (prefixed) names.

=head1 SEE ALSO

L<WEC::SSL::Errors>,
L<WEC::SSL::BigInt::rand|WEC::SSL::BigInt/rand>,
L<WEC::SSL::BigInt::pseudo_rand|WEC::SSL::BigInt/pseudo_rand>,
L<WEC::SSL::BigInt::rand_prime|WEC::SSL::BigInt/rand_prime>,
L<WEC::SSL::BigInt::rand_bits|WEC::SSL::BigInt/rand_bits>,
L<WEC::SSL::BigInt::pseudo_rand_bits|WEC::SSL::BigInt/pseudo_rand_bits>

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL-Rand@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
