package WEC::SSL::BigInt;
use 5.006001;
use strict;
use warnings;

our $VERSION = "1.000";

# Load XS prerequisites
require WEC::SSL::Utils;

require XSLoader;
XSLoader::load('WEC::SSL::BigInt', $VERSION);

use Exporter::Tidy
    constants => [qw(ZERO ONE MAX_WORD PERL_MAX_WORD)],
    tests     => [qw(is_zero is_non_zero is_even is_odd is_one is_prime
                     cmp abs_cmp eq ne lt le gt ge sign)],
    operations => [qw(add subtract multiply quotient divide perl_divide
                      modulo perl_modulo remainder perl_remainder
                      abs_remainder perl_abs_remainder
                      gcd pow square abs and or xor
                      negate complement inc inc_mutate dec dec_mutate abs int
                      perl_int perl_abs perl_inc perl_dec
                      mask_bits abs_mask_bits copy_sign)],
    mod_operations => [qw(mod_inverse mod_add mod_subtract mod_multiply
                          mod_pow mod_square)],
    prints	=> [qw(print_HEX print_hex print bio_print_HEX)],
    other => [qw(lshift1 lshift rshift1 rshift copy
                 mod_add mod_subtract mod_multiply mod_square mod_pow
                 bit_length byte_length bit abs_bit
                 to_decimal to_integer abs_to_integer to_hex to_HEX
                 to_mpi to_bin abs_to_bin
                 rand pseudo_rand rand_prime rand_bits pseudo_rand_bits
                 clear sensitive taint)];

sub to_filehandle {
    my ($fh) = @_;
    return if !defined $fh;
    my $caller = 1;
    while (my $package = caller($caller++)) {
        my $tmp = $fh=~/[\':]/ ? $fh : "${package}::$fh";
        return $tmp if defined fileno $tmp;
    }
    return $fh;
}

sub print_HEX($;*) {
    return print shift->to_HEX if @_ <= 1;
    no strict "refs";
    return print {ref $_[1] ? $_[1] : to_filehandle($_[1])} $_[0]->to_HEX;
}

sub print_hex($;*) {
    return print shift->to_hex if @_ <= 1;
    no strict "refs";
    return print {ref $_[1] ? $_[1] : to_filehandle($_[1])} $_[0]->to_hex;
}

sub print($;*) {
    return print shift->to_decimal if @_ <= 1;
    no strict "refs";
    return print {ref $_[1] ? $_[1] : to_filehandle($_[1])} $_[0]->to_decimal;
}

use overload
    "+"    => \&add,
    "+="   => \&add,
    "-"    => \&subtract,
    "-="   => \&subtract,
    "*"    => \&multiply,
    "*="   => \&multiply,
    "/"    => \&quotient,
    "/="   => \&quotient,
    "%"	   => \&modulo,
    "%="   => \&modulo,
    "**"   => \&pow,
    "**="  => \&pow,
    "<<"   => \&lshift,
    "<<="  => \&lshift,
    ">>"   => \&rshift,
    ">>="  => \&rshift,
    "++"   => \&inc_mutate,
    "--"   => \&dec_mutate,
    "<=>"  => \&cmp,
    "=="   => \&eq,
    "!="   => \&ne,
    "<"	   => \&lt,
    "<="   => \&le,
    ">"	   => \&gt,
    ">="   => \&ge,
    "neg"  => \&negate,
    "~"    => \&complement,
    "&"	   => \&and,
    "&="   => \&and,
    "|"	   => \&or,
    "|="   => \&or,
    "^"	   => \&xor,
    "^="   => \&xor,
    "!"	   => \&is_zero,
    "abs"  => \&abs,
    "int"  => \&int,
    '""'   => \&to_decimal,
    "bool" => \&is_non_zero,
    "0+"   => \&perl_int,
    "="	   => \&copy;

1;
__END__

=head1 NAME

WEC::SSL::BigInt - OpenSSL multi-precision integer arithmetic

=head1 SYNOPSIS

 use WEC::SSL::BigInt;

 # Creation and value
 $big_int = WEC::SSL::BigInt->new("123456789" x 10);
 $new_int = $big_int->copy;

 $big_int           = WEC::SSL::BigInt->from_decimal("123456789" x 10);
 $big_sensitive_num = WEC::SSL::BigInt->from_decimal("123456789" x 10, $sensitive);
 $string            = "$big_int";
 $string            = $big_int->to_decimal;

 $big_int           = WEC::SSL::BigInt->from_hex("123456789abcdef" x 10);
 $big_sensitive     = WEC::SSL::BigInt->from_hex("123456789abcdef" x 10, $sensitive);
 $hex_string        = $big_int->to_hex;      # Gives "123456789abcdef" x 10
 $hex_string        = $big_int->to_HEX;      # Gives "123456789ABCDEF" x 10
 $hex_string        = $big_int->to_hex(1);   # Result guaranteed even length

 $big_int           = WEC::SSL::BigInt->from_mpi(pack("N/C", @bytes));
 $big_int_sensitive = WEC::SSL::BigInt->from_mpi(pack("N/C", @bytes), $sensitive);
 $mpi_string        = $big_int->to_mpi;      # Gives pack("N/C", @bytes)

 $big_int           = WEC::SSL::BigInt->from_bin(pack("C*", @bytes));
 $big_int_sensitive = WEC::SSL::BigInt->from_bin(pack("C*", @bytes), $sensitive);
 $bin_string        = $big_int->to_bin;      # Gives pack("C*", @bytes)
 $bin_string        = $big_int->abs_to_bin;  # Gives pack("C*", @bytes)

 # Constants
 $zero              = WEC::SSL::BigInt->ZERO;
 $zero              = WEC::SSL::BigInt::ZERO();
 $one               = WEC::SSL::BigInt->ONE;
 $one               = WEC::SSL::BigInt::ONE();
 $max_word          = WEC::SSL::BigInt->MAX_WORD;
 $max_word          = WEC::SSL::BigInt::MAX_WORD();
 $max_int           = WEC::SSL::BigInt::PERL_MAX_WORD();

 # Operations
 $sum = WEC::SSL::BigInt::add($arg1, $arg2);
 $sum = WEC::SSL::BigInt::add($arg1, $arg2, 0);
 $sum = WEC::SSL::BigInt::add($arg2, $arg1, 1);
 $sum = WEC::SSL::BigInt::add($arg1, $arg2, undef);
 $sum = $arg1->add($arg2);
 $sum = $arg1->add($arg2, $how);
 $sum = $arg1 + $arg2;
 $sum += $arg;
 # All other overloaded binary operators have the forms of add above,
 # but from here on we'll only mention the method call and operator
 # version

 $diff = $arg1->subtract($arg2);
 $diff = $arg1 - $arg2;

 $product = $arg1->multiply($arg2);
 $product = $arg1 * $arg2;

 $quotient = $arg1->quotient($arg2);
 $quotient = $arg1 / $arg2;

 $quotient = $arg1->divide($arg2);
 ($quotient, $remainder) = $arg1->divide($arg2);
 $quotient = $arg1->perl_divide($arg2);
 ($quotient, $remainder) = $arg1->perl_divide($arg2);

 $remainder = $arg1->remainder($arg2);
 $remainder = $arg1->perl_remainder($arg2);
 $abs_remainder = $arg1->abs_remainder($arg2);
 $abs_remainder = $arg1->perl_abs_remainder($arg2);
 $modulo = $arg1->modulo($arg2);
 $modulo = $arg1 % $arg2;
 $modulo = $arg1->perl_modulo($arg2);

 $pow    = $arg1->pow($arg2);
 $pow    = $arg1 ** $arg2;

 $and    = $arg1->and($arg2);
 $and    = $arg1 & $arg2;

 $or     = $arg1->or($arg2);
 $or     = $arg1 | $arg2;

 $xor    = $arg1->xor($arg2);
 $xor    = $arg1 ^ $arg2;

 $shift  = $arg1->lshift($arg2);
 $shift  = $arg1 << $arg2;
 $shift  = $arg1->rshift($arg2);
 $shift  = $arg1 >> $arg2;

 $shift = $arg->lshift1;
 $shift = $arg->rshift1;

 $gcd   = $arg1->gcd($arg2);
 $inverse = $arg->mod_inverse($m);
 $square = $arg->mod_square($m);
 $sum  = $arg1->mod_add($arg2, $m);
 $diff = $arg1->mod_subtract($arg2, $m);
 $prod = $arg1->mod_multiply($arg2, $m);
 $exp  = $arg1->mod_pow($arg2, $m);
 $signed = $arg1->copy_sign($arg2);

 # Checks
 $sign = $big_int->sign;
 $bool = $big_int->is_zero;
 $bool = !$big_int;
 $bool = $big_int->is_non_zero;
 $bool = $big_int->is_one;

 # Compares
 $cmp = $arg1->cmp($arg2);
 $cmp = $arg1 <=> $arg2;
 $cmp = $arg1->abs_cmp($arg2);

 $bool = $arg1->eq($arg2);
 $bool = $arg1 == $arg2;

 $bool = $arg1->ne($arg2);
 $bool = $arg1 != $arg2;

 $bool = $arg1->lt($arg2);
 $bool = $arg1 < $arg2;

 $bool = $arg1->le($arg2);
 $bool = $arg1 <= $arg2;

 $bool = $arg1->gt($arg2);
 $bool = $arg1 > $arg2;

 $bool = $arg1->ge($arg2);
 $bool = $arg1 >= $arg2;

 $negated = WEC::SSL::BigInt::negate($arg);
 $negated = WEC::SSL::BigInt::negate($arg, $dummy);
 $negated = WEC::SSL::BigInt::negate($arg, $dummy, $how);
 $negated = WEC::SSL::BigInt::negate($arg, $dummy, undef);
 $negated = $arg1->negate;
 $negated = $arg1->negate($dummy);
 $negated = $arg1->negate($dummy, $how);
 $negated = -$arg1;

 # All other overloaded unary operators have the forms of negate above,
 # but from here on we'll only mention the method call and operator
 # version

 $complement = $arg->complement;
 $complement = ~ $arg;

 $int = $arg->int;
 $int = int $arg;
 $int = $arg->perl_int;
 $int = $arg->to_integer;

 $abs = $arg->abs;
 $abs = abs $arg;
 $abs = $arg->perl_abs;
 $abs = $arg->abs_to_integer;

 $old = $arg++;
 $new = ++$arg;
 $new = $arg->inc;
 $new = $arg->inc_mutate;
 $old = $arg--;
 $new = --$arg;
 $new = $arg->dec;
 $new = $arg->dec_mutate;

 $square = $arg->square;

 # Bit operations (see also "and", "or" and "xor")
 $bits  = $arg->bit_length;
 $bytes = $arg->byte_length;
 $bit = $arg->bit($bit_nr);
 $old_bit = $arg->bit($bit_nr, $new_bit);
 $bit = $arg->abs_bit($bit_nr);
 $old_bit = $arg->abs_bit($bit_nr, $new_bit);
 my $masked = mask_bits($arg, $bit_length);
 my $masked = abs_mask_bits($arg, $bit_length);

 # Sensitivity and tainting
 $sensitive     = $arg->sensitive;
 $old_sensitive = $arg->sensitive($new_sensitive);
 $taint         = $arg->taint;
 $old_taint     = $arg->taint($new_tainted);
 $arg->clear;

 # Primes
 $prime = WEC::SSL::BigInt->rand_prime(%options);
 $bool = $arg->is_prime;
 $bool = $arg->is_prime(%options);

 # Random numbers
 $rand = $limit->rand;
 $rand = $limit->pseudo_rand;
 $rand = WEC::SSL::BigInt->rand_bits(%options);
 $rand = WEC::SSL::BigInt->pseudo_rand_bits(%options);

 # Output
 $printed = $val->print;
 $printed = $val->print($fh);
 $printed = $val->print_hex;
 $printed = $val->print_hex($fh);
 $printed = $val->print_HEX;
 $printed = $val->print_HEX($fh);
 $printed = $val->bio_print_HEX($bio);

=head1 DESCRIPTION

If you need to do many modulo and/or divide operations with the same divisor,
see L<WEC::SSL::Reciprocal|WEC::SSL::Reciprocal>.

=head1 EXAMPLE1

Suppose we want to calculate 365 ** 1234 / 28:

  use WEC::SSL::BigInt;

  # Create a new BigInt with value 365
  my $num = WEC::SSL::BigInt->new(365);

  # Explicitly call the pow function.
  # Neither argument really has to be a BigInt
  my $num2 = WEC::SSL::BigInt::pow($num, 1234);

  # Or use an OO style of calling
  my $num3 = $num2->quotient(28);

  # Convert the result to a decimal string and print that
  print $num3->to_decimal;

=head1 EXAMPLE2

However, the previous example is unnecessarily complicated. You can just
depend on perl overloads as long as you make sure that for each operation at
least one argument is a BigInt:

  use WEC::SSL::BigInt;
  print WEC::SSL::BigInt->new(365) ** 1234 / 28

=head1 METHODS

See L<the add method|"add"> for the general philosophy behind the overloaded
binary operators.

See L<the negate method|"negate"> for the general philosophy behind the
overloaded unary operators.

=over 4

=item X<new>WEC::SSL::BigInt->new($string_or_number)

Creates a new WEC::SSL::BigInt object based on the given argument. The argument
may be a perl number or string (or anything that stringifies to
something that looks like a number). If the argument is not an exact integer,
the value truncated towards zero is used. Remember that you will get rounding
artefacts for sufficiently big floats (but not if they are specified as a
string). Trying to convert infinity or NaN (in either numeric or string from)
will raise an exception.
The returned value is not sensitive.

If the argument is already a WEC::SSL::BigInt object, returns a direct copy of
the argument without going through the string representation. The result will
be blessed into the given class, which is not necessarily equal to the argument
class. The returned value has the sensitivity of the argument.

For example, this will print a 1 followed by 10000 zeroes:

  print WEC::SSL::BigInt->new("1e10000")

=item X<copy>$new_int = $big_int->copy

Makes a copy of the value, sensitivity and taintedness of $big_int and
returns it as $new_int. The exact type of $big_int is lost, the result is
always a WEC::SSL::BigInt object.

=item X<from_decimal>WEC::SSL::BigInt->from_decimal($string)

=item X<from_decimal_sensitive>WEC::SSL::BigInt->from_decimal($string, $sensitive)

Creates a new WEC::SSL::BigInt object based on the given argument. The argument
string is the decimal representation of the wanted number. The string should
match /^[ \t\n\r\f]*[+-]?[0-9]+\z/. The returned value is not sensitive by
default.

If the argument is an WEC::SSL::BigInt object it may seem you get a simple
copy, but what really happens is that the argument gets converted to a decimal
string, which then in turn is converted back to a WEC::SSL::BigInt object
(which will be non-sensitive by default even if the original was). That is
rather inefficient, so don't do that (see L<new|"new"> or L<copy|"copy">
instead).

If there is a $sensitive argument, makes the result sensitive if that is true.

This method is a wrapper for OpenSSL function L<BN_dec2bn|BN_dec2bn(3)>.

=item X<to_decimal>$big_int->to_decimal

Returns the decimal expansion of $big_int as a string that matches
/^-?[0-9]+\z/. This is also the function that WEC::SSL::BigInt stringification
is overloaded to.

This method is a wrapper for OpenSSL function L<BN_bn2dec|BN_bn2dec(3)>.

=item X<from_hex>WEC::SSL::BigInt->from_hex($string)

=item X<from_hex_sensitive>WEC::SSL::BigInt->from_hex($string, $sensitive)

Creates a new WEC::SSL::BigInt object based on the given argument. The argument
string is the hexadecimal representation of the wanted number. The string
should match /^[ \t\n\r\f]*[+-]?[0-9a-fA-F]+\z/. In particular, the string
should not start with "0x". The returned value is not sensitive by default.

If the argument is an WEC::SSL::BigInt object, that will get converted to a
decimal string and then interpreted as a hexadecimal string, which will
result in some totally different number. So you probably don't want to do
that (see L<new|"new"> or L<copy|"copy"> instead).

If there is a $sensitive argument, makes the result sensitive if that is true.

This method is a wrapper for OpenSSL function L<BN_hex2bn|BN_hex2bn(3)>.

=item X<to_hex>$big_int->to_hex

=item X<to_hex_even>$big_int->to_hex($even)

=item X<to_HEX>$big_int->to_HEX

=item X<to_HEX_even>$big_int->to_HEX($even)

Returns the hexadecimal expansion of $big_int as a string. For to_hex
the result will be in lowercase, for to_HEX it will be uppercase. If $even is
not given, the result will be without unnecessary leading zeroes. If $even is
given and true, enough leading zeros will be added to make the numeric part
of even length. The same is done if $even is false, except that 0 will
represented as a simple "0".

These methods are wrappers for OpenSSL function L<BN_bn2hex|BN_bn2hex(3)>.

=item X<from_mpi>$big_int = WEC::SSL::BigInt->from_mpi(pack("N/C", @bytes))

=item X<from_mpi_sensitive>$big_int_sensitive = WEC::SSL::BigInt->from_mpi(pack("N/C", @bytes), $sensitive)

Converts a string in mpi format to the corresponding big integer.

X<mpi> MPI format consists of the numbers length represented as a 4-byte
big-endian number, followed by that number of bytes representing the number in
big-endian order. The most significant bit indicates the sign of the result
(0 for positive, 1 for negative). This implies that the number gets an extra
byte in front if its most significant bit is set.

As you can see, the MPI format provides a simple, efficient and portable
serialization of big numbers.

If there is a $sensitive argument, makes the result sensitive if that is true.

This method is a wrapper for OpenSSL function L<BN_mpi2bn|BN_mpi2bn(3)>.

(In case you actually want to use the pack "N/C" notation, remember that that
only works in perl 5.9.2 and higher).

  print WEC::SSL::BigInt->from_mpi("\x00\x00\x00\x02\x01\x00")

will print

  256

=item X<to_mpi>$mpi_string = $big_int->to_mpi

Given an integer, converts it to L<MPI format|"MPI">
(see L<from_mpi|"from_mpi">).

This method is a wrapper for OpenSSL function L<BN_bn2mpi|BN_bn2mpi(3)>.

=item X<from_bin>$big_int = WEC::SSL::BigInt->from_bin(pack("C*", @bytes))

=item X<from_bin_sensitive>$big_int_sensitive = WEC::SSL::BigInt->from_bin(pack("C*", @bytes), $sensitive)

Converts a big endian byte sequence to the corresponding non-negative integer.

If there is a $sensitive argument, makes the result sensitive if that is true.

  print WEC::SSL::BigInt->from_bin("\x01\x00")

will print

  256

This method is a wrapper for OpenSSL function L<BN_bin2bn|BN_bin2bn(3)>.

=item X<to_bin>$bin_string = $big_int->to_bin

Converts a non-negative integer to a big-endian byte sequence.

Raises an exception if applied to a negative argument.

This method is a wrapper for for OpenSSL function L<BN_bn2bin|BN_bn2bin(3)>.

=item X<abs_to_bin>$bin_string = $big_int->to_bin

Converts the absolute value of an integer to a big-endian byte sequence.

This method is a wrapper for for OpenSSL function L<BN_bn2bin|BN_bn2bin(3)>.

=item X<ZERO>$zero = WEC::SSL::BigInt->ZERO

=item $zero = WEC::SSL::BigInt::ZERO()

Returns a new big integer with the value 0.

This method is a wrapper for OpenSSL function L<BN_zero|BN_zero(3)>.

=item X<ONE>$one = WEC::SSL::BigInt->ONE

=item $one = WEC::SSL::BigInt::ONE()

Returns a new big integer with the value 1.

This method is a wrapper for OpenSSL function L<BN_one|BN_one(3)>.

=item X<MAX_WORD>$max_word = WEC::SSL::BigInt->MAX_WORD

=item $max_word = WEC::SSL::BigInt::MAX_WORD()

Returns a new big integer with a value equal to the greatest value that can
be represented with the OpenSSL internal type BN_ULONG (where the sign is
usually an extra external bit). When the documentation of other methods in this
module talks about "small enough integers", this is one of the limiting values,
the other being the range of values representable with the applicable internal
perl types (these you can determine by starting from ~0, possibly shifted right
by one bit to make place for a sign bit).

This method is a wrapper for OpenSSL constant BN_MASK2.

=item X<PERL_MAX_WORD>$max_int = WEC::SSL::BigInt::PERL_MAX_WORD()

Returns a perl integer with a value equal to the minimum of
L<MAX_WORD|"MAX_WORD"> and UV_MAX (the value perl returns for ~0) and
represents the maximal integer that is "simple" both from the view of perl and
OpenSSL. At the negative side the extreme value will be -min(MAX_WORD, ~0/2+1.

=item X<add>$sum = WEC::SSL::BigInt::add($arg1, $arg2)

This is the basic form of a binary operator. It will take arguments $arg1
and $arg2 and return their sum. If either or both aren't WEC::SSL::BigInt
objects, they will be used as arguments to a L<WEC::SSL::BigInt-E<gt>new|"new">
before being passed to the addition routine.

The result is sensitive if and only if either of the arguments is sensitive.

This method is normally a wrapper for OpenSSL function L<BN_add|BN_add(3)>.
But if the second argument is a small enough perl number, it will in fact not
bother to convert it to a WEC::SSL::BigInt internally, but directly use its
value with L<BN_add_word|BN_add_word(3)> or L<BN_sub_word|BN_sub_word(3)>.
If the two arguments refer to the same object, it will use
L<BN_lshift1|BN_lshift1(3)>.

=item $sum = WEC::SSL::BigInt::add($arg1, $arg2, $false)

For any false value of $false (except undef) this is the same as

  $sum = WEC::SSL::BigInt::add($arg1, $arg2);

=item $sum = WEC::SSL::BigInt::add($arg1, $arg2, undef)

This is the same as:

  $sum = WEC::SSL::BigInt::add($arg1, $arg2);

except that add is now free to reuse $arg1 for the result. Whether it actually
does is an implementation detail and may depend on which operation is being
executed, so it's not certain that $arg1 will be the same as $sum.

=item $sum = WEC::SSL::BigInt::add($arg2, $arg1, $true)

For any true value $true this reverses the arguments, so it's the same as:

  $sum = WEC::SSL::BigInt::add($arg1, $arg2);

(except that it's still $arg1 that counts as second argument that won't
be internally converted to a WEC::SSL::BigInt if its value is a small enough
perl number)

For addition this doesn't make any difference, but it does for operations
like L<subtract|"subtract">

=item $sum = $arg1->add($arg2)

=item $sum = $arg1->add($arg2, $how)

You can obviously also use these functions as method calls, so these are
equivalent to:

  $sum = WEC::SSL::BigInt::add($arg1, $arg2);
  $sum = WEC::SSL::BigInt::add($arg1, $arg2, $how);

=item $sum = $arg1 + $arg2

Operator "+" is L<overloaded|overload> to L<add|"add"> (notice how the
$how argument has exactly the semantics needed for L<overload|overload>).

=item $sum += $arg

Operator "+=" is also L<overloaded|overload> to L<add|"add">. Perl will
make sure to first call a copy constructor on $sum in case there are multiple
referents to it, so for code like:

  $other = $foo;	# This makes $other and $foo aliases
  $foo += $bar;		# This essentially does:
                        #   $foo = $foo->copy;
                        #   $foo = WEC::SSL::BigInt::add($foo, $bar, undef);

Or, to be more explicit:

  use WEC::SSL::BigInt;

  my $five  = WEC::SSL::BigInt->new(5);
  my $three = WEC::SSL::BigInt->new(3);
  my $sum = $five;
  $sum = $sum->add($three, undef);
  print "sum=$sum";
  print "five=$five";

which will print:

  sum=8
  five=8

Versus:

  use WEC::SSL::BigInt;

  my $five  = WEC::SSL::BigInt->new(5);
  my $three = WEC::SSL::BigInt->new(3);
  my $sum = $five;
  $sum += $three;
  print "sum=$sum";
  print "five=$five";

Which will print:

  sum=8
  five=5

So it's probably easier to avoid aliasing errors when using the overloaded
version of the operators.

=item X<subtract>$diff = $arg1->subtract($arg2)

=item $diff = $arg1 - $arg2

Subtracts $arg2 from $arg1.

This method is normally a wrapper for OpenSSL function L<BN_sub|BN_sub(3)>.
However, if the second argument is a small enough perl number, it will
not internally convert it to a WEC::SSL::BigInt object and use
L<BN_sub_word|BN_sub_word(3)> or L<BN_add_word|BN_add_word(3)> instead.
If $arg1 and $arg2 refer to the same object, it will directly use
L<BN_zero|BN_zero(3)>.

=item X<multiply>$product = $arg1->multiply($arg2)

=item $product = $arg1 * $arg2

Multiplies $arg1 by $arg2

This method is normally a wrapper for OpenSSL function L<BN_mul|BN_mul(3)>.
If both arguments refer to the same object, it will use L<BN_sqr|BN_sqr(3)>
instead. If the second argument is a small enough perl number, it does not
internally convert it to a WEC::SSL::BigInt object, but directly uses
L<BN_mul_word|BN_mul_word(3)>

=item X<quotient>$quotient = $arg1->quotient($arg2)

=item $quotient = $arg1 / $arg2

Divides $arg1 by $arg2 and returns the integer part of the result
(truncated toward zero). $arg2 == 0 will raise an exception.

 $arg1 $arg2  $quotient
 -15  / -7  =  2
 -15  /  7  = -2
  15  / -7  = -2
  15  /  7  =  2

This method is a wrapper for OpenSSL function L<BN_div|BN_div(3)>, except when
$arg2 is a sufficiently small perl integer, in which case it will use
L<BN_div_word|BN_div_word(3)>.

=item X<divide>($quotient, $remainder) = $arg1->divide($arg2)

=item $quotient = $arg1->divide($arg2)

Divides $arg1 by $arg2 and returns the integer part of the result
(truncated toward zero) as quotient and $remainder = $arg1 - $quotient * $arg2

Returns just the quotient in scalar context (identical to
L<quotient|"quotient">).

$arg2 == 0 will raise an exception.

         $arg1 $arg2   $quotient $remainder
  divide(-15  ,  -7) = (  2,     -1)
  divide(-15  ,   7) = ( -2,     -1)
  divide( 15  ,  -7) = ( -2,      1)
  divide( 15  ,   7) = (  2,      1)

This method is usually a wrapper for OpenSSL function L<BN_div|BN_div(3)>.
If $arg1 refers to the same object as $arg2, it uses L<BN_zero|BN_zero(3)> and
L<BN_one|BN_one(3)> (after checking if $arg2 is not 0). Uses
L<BN_div_word|BN_div_word(3)> in case $arg2 is a small enough perl number
(even when $how indicates the arguments are reversed), but still returns the
remainder part as a WEC::SSL::BigInt object reference (even though it could be
represented as a small perl number).

=item X<perl_divide>($quotient, $remainder) = $arg1->perl_divide($arg2)

=item $quotient = $arg1->perl_divide($arg2)

These are exactly like L<divide|"divide"> except that the remainder is
returned as a perl number instead of as a WEC::SSL::BigInt object.

Divides $arg1 by $arg2 and returns the integer part of the result
(truncated toward zero) as quotient and $remainder = $arg1 - $quotient * $arg2

Returns just the quotient in scalar context (identical to
L<quotient|"quotient">, so for this case there is no difference with
L<divide|"divide">).

$arg2 == 0 will raise an exception.

              $arg1 $arg2   $quotient $remainder
  perl_divide(-15  ,  -7) = (  2,     -1)
  perl_divide(-15  ,   7) = ( -2,     -1)
  perl_divide( 15  ,  -7) = ( -2,      1)
  perl_divide( 15  ,   7) = (  2,      1)

This method is usually a wrapper for OpenSSL function L<BN_div|BN_div(3)>.
If $arg1 refers to the same object as $arg2, it uses L<BN_zero|BN_zero(3)>
for the quotient (after checking if $arg2 is not 0). Uses
L<BN_div_word|BN_div_word(3)> in case $arg2 is a small enough perl number
(even when $how indicates the arguments are reversed). Always returns the
remainder part as perl number, even if that leads to loss of precision.
However, if $arg2 is small enough you can be sure that can't happen.

=item X<remainder>$remainder = $arg1->remainder($arg2)

Divides $arg1 by $arg2 and returns the remainder. This corresponds to what
perl operator % will do under L<use integer|integer> on most architectures.
$arg2 == 0 will raise an exception.

 $remainder = $arg1 - $quotient * $arg2

            $arg1 $arg2  $remainder
  remainder(-15,  -7)  = -1
  remainder(-15,   7)  = -1
  remainder( 15,  -7)  =  1
  remainder( 15,   7)  =  1

This method is a wrapper for OpenSSL function L<BN_mod|BN_mod(3)> or
L<BN_mod_word|BN_mod_word(3)> if $arg2 is a small enough perl number.

=item X<perl_remainder>$remainder = $arg1->perl_remainder($arg2)

This function is exactly like L<remainder|"remainder"> except that the result
is returned as a perl number instead of as a WEC::SSL::BigInt object.

Divides $arg1 by $arg2 and returns the remainder. This corresponds to what
perl operator % will do under L<use integer|integer> on most architectures.
$arg2 == 0 will raise an exception.

 $remainder = $arg1 - $quotient * $arg2

                 $arg1 $arg2  $remainder
  perl_remainder(-15,  -7)  = -1
  perl_remainder(-15,   7)  = -1
  perl_remainder( 15,  -7)  =  1
  perl_remainder( 15,   7)  =  1

This method is a wrapper for OpenSSL function L<BN_mod|BN_mod(3)> or
L<BN_mod_word|BN_mod_word(3)> if $arg2 is a small enough perl number.

=item X<abs_remainder>$abs_remainder = $arg1->abs_remainder($arg2)

Divides $arg1 by abs($arg2) and returns the remainder brought into the
range [0..abs($arg2)-1]. $arg2 == 0 will raise an exception.

                $arg1 $arg2  $abs_remainder
  abs_remainder(-15,  -7)  = 6
  abs_remainder(-15,   7)  = 6
  abs_remainder( 15,  -7)  = 1
  abs_remainder( 15,   7)  = 1

This method is a wrapper for OpenSSL function L<BN_nnmod|BN_nnmod(3)> or
L<BN_mod_word|BN_mod_word(3)> if $arg2 is a small enough perl number.

=item X<perl_abs_remainder>$abs_remainder = $arg1->perl_abs_remainder($arg2)

This function is exactly like L<abs_remainder|"abs_remainder"> except that the
result is returned as a perl number instead of as a WEC::SSL::BigInt object.

Divides $arg1 by abs($arg2) and returns the remainder brought into the
range [0..abs($arg2)-1]. $arg2 == 0 will raise an exception.

                     $arg1 $arg2  $abs_remainder
  perl_abs_remainder(-15,  -7)  = 6
  perl_abs_remainder(-15,   7)  = 6
  perl_abs_remainder( 15,  -7)  = 1
  perl_abs_remainder( 15,   7)  = 1

This method is a wrapper for OpenSSL function L<BN_nnmod|BN_nnmod(3)> or
L<BN_mod_word|BN_mod_word(3)> if $arg2 is a small enough perl number.

=item X<modulo>$modulo = $arg1->modulo($arg2)

=item $modulo = $arg1 % $arg2

Divides $arg1 by $arg2 and returns the remainder, but with the same sign rules
as these of the perl % operator (without L<use integer|integer>). This method
is therefore the one overloaded to %. $arg2 == 0 will raise an exception.

         $arg1 $arg2   $modulo
  modulo(-15,  -7)  =  -1
  modulo(-15,   7)  =   6
  modulo( 15,  -7)  =  -6
  modulo( 15,   7)  =   1

This method is a wrapper for OpenSSL function L<BN_mod|BN_mod(3)> or
L<BN_mod_word|BN_mod_word(3)> if $arg2 is a small enough perl number.

=item X<perl_modulo>$modulo = $arg1->perl_modulo($arg2)

This function is exactly like L<modulo|"modulo"> except that the result is
returned as a perl number instead of as a WEC::SSL::BigInt object.

Divides $arg1 by $arg2 and returns the remainder, but with the same sign rules
as these of the perl % operator (without L<use integer|integer>). $arg2 == 0
will raise an exception.

              $arg1 $arg2   $modulo
  perl_modulo(-15,  -7)  =  -1
  perl_modulo(-15,   7)  =   6
  perl_modulo( 15,  -7)  =  -6
  perl_modulo( 15,   7)  =   1

This method is a wrapper for OpenSSL function L<BN_mod|BN_mod(3)> or
L<BN_mod_word|BN_mod_word(3)> if $arg2 is a small enough perl number.

=item X<pow>$pow = $arg1->pow($arg2)

=item $pow = $arg1 ** $arg2

Raises $arg1 to the power $arg2. $arg2 < 0 will raise an exception. 0**0 is 1.

      $arg1 $arg2   $modulo
  pow(-15,   7)  = -170859375
  pow( 15,   7)  =  170859375
  pow( 0,    0)  =  1

  pow(-15,  -7)    Negative exponent not supported
  pow( 15,  -7)    Negative exponent not supported

This method is a wrapper for OpenSSL function L<BN_exp|BN_exp(3)> or
(repeated) <BN_sqr|BN_sqr(3)> and <BN_mul|BN_mul(3)> if $arg2 is a small
enough perl number.

=item X<and>$and = $arg1->and($arg2)

=item $and = $arg1 & $arg2

For the bitops, WEC::SSL::BigInts are viewed as 2-complement bitstrings
with an infinite sequence of zeros to the left for positive numbers and
and infinite sequence of ones on the left for negative numbers. Under this
view the and operator is simply bitwise and. This is the same behavior as
perl bitwise and has under L<use integer|integer> on most architectures.

      $arg1 $arg2  $and
  and(-12,  -9)  = -12
  and(-12,   9)  =   0
  and( 12,  -9)  =   4
  and( 12,   9)  =   8

=item X<or>$or = $arg1->or($arg2)

=item $or = $arg1 | $arg2

Does a bitwise or of the 2-complement bitstrings. This is the same behavior as
perl bitwise or has under L<use integer|integer> on most architectures.

     $arg1 $arg2  $or
  or(-12,  -9)  = -9
  or(-12,   9)  = -3
  or( 12,  -9)  = -1
  or( 12,   9)  =  13

=item X<xor>$xor    = $arg1->xor($arg2)

=item $xor = $arg1 ^ $arg2

Does a bitwise xor of the 2-complement bitstrings. This is the same behavior
as perl bitwise xor has under L<use integer|integer> on most architectures.

      $arg1 $arg2  $xor
  xor(-12,  -9)  =  3
  xor(-12,   9)  = -3
  xor( 12,  -9)  = -5
  xor( 12,   9)  =  5

=item X<lshift>$shift  = $arg1->lshift($arg2)

=item $shift  = $arg1 << $arg2

Does a left shift by $arg2 bits on the 2-complement bitstring of $arg1. Shifts
right in case $arg2 is negative.

         $arg1 $arg2  $shift
  lshift(-15,  -2)  =  -4
  lshift(-15,   2)  = -60
  lshift( 15,  -2)  =   3
  lshift( 15,   2)  =  60

This method is a wrapper for OpenSSL functions L<BN_lshift|BN_lshift(3)> and
L<BN_rshift|BN_rshift(3)>.

=item X<rshift>$shift  = $arg1->rshift($arg2)

=item $shift = $arg1 >> $arg2

Does a right shift by $arg2 bits on the 2-complement bitstring of $arg1. Shifts
left in case $arg2 is negative.

         $arg1 $arg2  $shift
  rshift(-15,  -2)  = -60
  rshift(-15,   2)  =  -4
  rshift( 15,  -2)  =  60
  rshift( 15,   2)  =   3

This method is a wrapper for OpenSSL functions L<BN_rshift|BN_rshift(3)> and
L<BN_lshift|BN_lshift(3)>. If possible, they will in fact use
L<BN_lshift1|BN_lshift1> and L<BN_rshift1|BN_rshift1>.

=item X<lshift1>$shift = $arg->lshift1

Essentially $shift = $arg->lshift(1)
Since lshift detects the special of a 1 argument, this won't be faster.

This method is a wrapper for OpenSSL functions L<BN_lshift1|BN_lshift1>

=item X<rshift1>$shift = $arg1->rshift1

Essentially $shift = $arg->rshift(1)
Since rshift detects the special case of a 1 argument, this won't be faster.

This method is a wrapper for OpenSSL functions L<BN_rshift1|BN_rshift1>

=item X<gcd>$gcd = $arg1->gcd($arg2)

Returns the biggest (positive) integer that divides both $arg1 and $arg2
(the greatest common divisor). gcd(0, 0) is undefined and will raise an
exception.

      $arg1 $arg2 $gcd
  gcd(-12,  -9) = 3
  gcd(-12,   9) = 3
  gcd( 12,  -9) = 3
  gcd( 12,   9) = 3

This method is a wrapper for OpenSSL function L<BN_gcd|BN_gcd(3)>

=item X<mod_inverse>$inverse = $arg->mod_inverse($m)

The inverse is the smallest integer in the range [0..abs($m)-1] such that

  $arg * $inverse == 1 (mod $m)

Will raise an exception if $m is 0 or if $arg and $m are not relatively prime.
Will return 0 if $m = 1

              $arg  $m    $inverse
  mod_inverse(-12,  -7) = 4
  mod_inverse(-12,   7) = 4
  mod_inverse( 12,  -7) = 3
  mod_inverse( 12,   7) = 3

This method is a wrapper for OpenSSL function
L<BN_mod_inverse|BN_mod_inverse(3)>

=item X<mod_square>$square = $arg->mod_square($m)

This is the same as

  $square = abs_remainder($arg **2, $m)

but more efficient.

Will raise an exception if $m is 0.

              $arg  $m    $square
  mod_square(-12,  -7) =  4	# 12**2 = 144 = 7*20+4
  mod_square(-12,   7) =  4
  mod_square( 12,  -7) =  4
  mod_square( 12,   7) =  4

This method is a wrapper for OpenSSL function L<BN_mod_sqr|BN_mod_sqr(3)>.

=item X<mod_add>$sum  = $arg1->mod_add($arg2, $m)

This is the same as

  $sum = abs_remainder($arg1+$arg2, $m)

but more efficient.

Will raise an exception if $m is 0.

          $arg1 $arg2 $m    $prod
  mod_add(-12,  0,    -7) = 2
  mod_add(-12,  0,     7) = 2
  mod_add( 12,  0,    -7) = 5
  mod_add( 12,  0,     7) = 5

This method is a wrapper for OpenSSL function L<BN_mod_add|BN_mod_add(3)>.

=item X<mod_subtract>$diff = $arg1->mod_subtract($arg2, $m)

This is the same as

  $diff = abs_remainder($arg1-$arg2, $m)

but more efficient.

Will raise an exception if $m is 0.

               $arg1 $arg2 $m    $prod
  mod_subtract(-12,  0,    -7) = 2
  mod_subtract(-12,  0,     7) = 2
  mod_subtract( 12,  0,    -7) = 5
  mod_subtract( 12,  0,     7) = 5

This method is a wrapper for OpenSSL function L<BN_mod_sub|BN_mod_sub(3)>.

=item X<mod_multiply>$prod = $arg1->mod_multiply($arg2, $m)

This is the same as

  $prod = abs_remainder($arg1*$arg2, $m)

but more efficient. In case $arg1 refers to the same number as $arg2 it will in
fact do a L<mod_square|"mod_square">.

               $arg1 $arg2 $m    $prod
  mod_multiply(-12,  1,    -7) = 2
  mod_multiply(-12,  1,     7) = 2
  mod_multiply( 12,  1,    -7) = 5
  mod_multiply( 12,  1,     7) = 5

Will raise an exception if $m is 0.

This method is a wrapper for OpenSSL function L<BN_mod_mul|BN_mod_mul(3)>
(or L<BN_mod_sqr|BN_mod_sqr(3)>)

=item X<mod_pow>$exp = $arg1->mod_pow($arg2, $m)

This is the same as

  $prod = abs_remainder($arg1**$arg2, $m)

but more efficient.

          $arg1 $arg2 $m    $prod
  mod_pow(-12,  1,    -7) = 2
  mod_pow(-12,  1,     7) = 2
  mod_pow( 12,  1,    -7) = 5
  mod_pow( 12,  1,     7) = 5

Will raise an exception if $m is 0.

This method is a wrapper for OpenSSL function L<BN_mod_exp|BN_mod_exp(3)>.

=item X<copy_sign>$signed = $arg1->copy_sign($arg2)

Takes the sign from $arg2, applies it to $arg1 and returns the result. If $arg2
is 0, 0 is returned. In this last case the sensitivity and taintedness of $arg1
may or may not propagate to the result.

This method counts as a binary operator, so it supports a third $how argument
which allows you to switch the arguments and to do a more efficient inplace
sign change.

            $arg1 $arg2 $signed
  copy_sign(-12,  -7) = -12
  copy_sign(-12,   0) =   0
  copy_sign(-12,   7) =  12
  copy_sign( 12,  -7) = -12
  copy_sign( 12,   0) =   0
  copy_sign( 12,   7) =  12

This method is a wrapper for for OpenSSL functions
L<BN_is_negative|BN_is_negative(3)> and L<BN_set_negative|BN_set_negative(3)>.

=item X<sign>$sign = $big_int->sign

Like int($sign) <=> 0. Returns -1 if $big_int < 0, 0 if $big_int == 0 and
1 if $big_int > 0.

This method is a wrapper for for OpenSSL functions
L<BN_is_negative|BN_is_negative(3)> and L<BN_is_zero|BN_is_zero(3)>.

=item X<is_zero>$bool = $big_int->is_zero

=item X<not>$bool = !$big_int

Return a true value if $big_int is zero, false otherwise. This won't be
that much than using the binary compare operators with a literal 0
as second argument because they are special cased for small perl integers.

This method is a wrapper for OpenSSL function L<BN_is_zero|BN_is_zero(3)>.

=item X<is_non_zero>$bool = $big_int->is_non_zero

Return a false value if $big_int is zero, true otherwise. This won't be
that much faster than using the binary compare operators with a literal 0
as second argument because they are special cased for small perl integers.

This method is a wrapper for OpenSSL function L<BN_is_zero|BN_is_zero(3)>.

=item X<is_one>$bool = $big_int->is_one

Return a true value if $big_int is one, false otherwise. This won't be
fundamentally faster than using the binary compare operators with a literal 1
as second argument because they are special cased for small perl integers.

This method is a wrapper for OpenSSL function L<BN_is_one|BN_is_one(3)>.

=item X<cmp>$cmp = $arg1->cmp($arg2)

=item $cmp = $arg1 <=> $arg2

Returns -1 if $arg1 < $arg2, 0 if $arg1 == $arg2 and 1 if $arg1 > $arg2.
Even though the method is named C<cmp>, this is a numeric compare, not a string
compare. The tainting state of the result is unspecified.

Remember that both arguments are (at least conceptually) converted to integers
before doing the compare, so -2.8 is equal to -2 for all the WEC::BigInt
compare operators.

This method does fast internals access if the second argument is a small enough
perl number and uses OpenSSL function L<BN_cmp|BN_cmp(3)> otherwise.

=item X<abs_cmp> $cmp = $arg1->abs_cmp($arg2)

Like L<cmp|"cmp">, but compare the absolute values of the arguments. So it's
conceptually equivalent to:

  $cmp = abs($arg1) <=> abs($arg2)

This method does fast internals access if the second argument is a small enough
perl number and uses OpenSSL function L<BN_ucmp|BN_ucmp(3)> otherwise.

=item X<eq>$bool = $arg1->eq($arg2)

=item $bool = $arg1 == $arg2

Returns true if $arg1 == $arg2, false otherwise.
Even though the method is named C<eq>, this is a numeric compare, not a string
compare. The tainting state of the result is unspecified.

This method is a wrapper for OpenSSL functions L<BN_cmp|BN_cmp(3)>,
L<BN_is_word|BN_is_word(3)> and L<BN_abs_is_word|BN_abs_is_word(3)>.

=item X<ne>$bool = $arg1->ne($arg2)

=item $bool = $arg1 != $arg2

Returns false if $arg1 == $arg2, true otherwise.
Even though the method is named C<ne>, this is a numeric compare, not a string
compare. The tainting state of the result is unspecified.

This method is a wrapper for OpenSSL functions L<BN_cmp|BN_cmp(3)>,
L<BN_is_word|BN_is_word(3)> and L<BN_abs_is_word|BN_abs_is_word(3)>.

=item X<lt>$bool = $arg1->lt($arg2)

=item $bool = $arg1 < $arg2

Returns true if $arg1 < $arg2, false otherwise.
Even though the method is named C<lt>, this is a numeric compare, not a string
compare. The tainting state of the result is unspecified.

This method does fast internals access if the second argument is a small enough
perl number and uses OpenSSL function L<BN_cmp|BN_cmp(3)> otherwise.

=item X<le>$bool = $arg1->le($arg2)

=item $bool = $arg1 <= $arg2

Returns true if $arg1 <= $arg2, false otherwise.
Even though the method is named C<le>, this is a numeric compare, not a string
compare. The tainting state of the result is unspecified.

This method does fast internals access if the second argument is a small enough
perl number and uses OpenSSL function L<BN_cmp|BN_cmp(3)> otherwise.

=item X<gt>$bool = $arg1->gt($arg2)

=item $bool = $arg1 > $arg2

Returns true if $arg1 > $arg2, false otherwise.
Even though the method is named C<gt>, this is a numeric compare, not a string
compare. The tainting state of the result is unspecified.

This method does fast internals access if the second argument is a small enough
perl number and uses OpenSSL function L<BN_cmp|BN_cmp(3)> otherwise.

=item X<ge>$bool = $arg1->ge($arg2)

=item $bool = $arg1 >= $arg2

Returns true if $arg1 >= $arg2, false otherwise.
Even though the method is named C<ge>, this is a numeric compare, not a string
compare. The tainting state of the result is unspecified.

This method does fast internals access if the second argument is a small enough
perl number and uses OpenSSL function L<BN_cmp|BN_cmp(3)> otherwise.

=item X<negate>$negated = WEC::SSL::BigInt::negate($arg)

This is the basic form of a unary operator. It will take arguments $arg
and return the negated value -$arg. If $arg isn't a WEC::SSL::BigInt
object, it will be used as argument to a L<WEC::SSL::BigInt-E<gt>new|"new">
before being passed to the negation routine.

The result is sensitive if and only if the argument is sensitive.

         $arg   $negated
  negate(-12) =  12
  negate( 12) = -12

This method is a wrapper for OpenSSL function
L<BN_set_negative|BN_set_negative(3)>.

=item $negated = WEC::SSL::BigInt::negate($arg, $dummy)

Unary operations accept a dummy argument that will be ignored, so this is the
same as

  $negated = WEC::SSL::BigInt::negate($arg)

=item $negated = WEC::SSL::BigInt::negate($arg1, $arg2, $how)

For any value of $how except undef this is the same as

  $negated = WEC::SSL::BigInt::negate($arg)

=item $negated = WEC::SSL::BigInt::negate($arg, $dummy, undef)

This is the same as:

  $negated = WEC::SSL::BigInt::negate($arg)

except that negate is now free to reuse $arg for the result. Whether it actually
does is an implementation detail and may depend on which operation is being
executed, so it's not certain that $arg will be the same as $negated.

=item $negated = $arg1->negate

=item $negated = $arg->negate($dummy)

=item $negated = $arg->negate($dummy, $how)

You can obviously also use these functions as method calls, so these are
equivalent to:

  $negated = WEC::SSL::BigInt::negate($arg);
  $negated = WEC::SSL::BigInt::negate($arg, $dummy);
  $negated = WEC::SSL::BigInt::negate($arg, $dummy, $how);

which in turn are all equivalent to the first one except if $how is undef.

=item $negate = - $arg

Operator "-" is L<overloaded|overload> to L<negate|"negate"> (notice how the
$how argument has exactly the semantics needed for L<overload|overload>).

All the unary operators have all these basic forms. But from here on we'll
only show the method style and the operator style.

=item X<complement>$complement = $arg->complement

=item $complement = ~ $arg

Complements the 2-complement bitstring representing $arg.

             $arg   $complement
  complement(-12) =  11
  complement( 12) = -13

This method is a wrapper for OpenSSL function
L<BN_set_negative|BN_set_negative(3)>.

=item X<int>$int = $arg->int

=item $int = int $arg

Returns the same value as the argument.

      $arg   $int
  int(-12) = -12
  int( 12) =  12

Mainly exists for completeness.

=item X<perl_int>$int = $arg->perl_int

Returns the argument as a perl number (IV, UV or NV). There may be loss of
precision if the number does not fit in an IV/UV. The result may be
infinite if it overflows an NV.

=item X<to_integer>$integer = $arg->to_integer

Returns the value of $arg as a plain perl integer (IV/UV).
Croaks on overflow. So it's certain there is no loss of precision if this
method returns successfully.

=item X<abs>$abs = $arg->abs

=item $abs = abs $arg

Returns the absolute value of the argument.

      $arg   $abs
  abs(-12) = 12
  abs( 12) = 12

This method is a wrapper for OpenSSL function
L<BN_set_negative|BN_set_negative(3)>.

=item X<perl_abs>$abs = $arg->perl_abs

Returns the absolute value of the argument as a perl number (IV, UV or NV).
There may be loss of precision if the number does not fit in an IV/UV. The
result may be infinite if it overflows an NV.

=item X<abs_to_integer>$abs = $arg->abs_to_integer

Returns the absolute value of $arg as a plain perl integer (IV or UV).
Croaks on overflow. So it's certain there is no loss of precision if this
method returns successfully.

=item X<post_inc>$old = $arg++

$arg is replaced by a L<copy|"copy"> which then gets incremented inplace
(so it loses the exact type and becomes a WEC::SSL::BigInt unless you overrode
copy for your derived type). The old value of $arg before the copy is returned.

This method is a wrapper for OpenSSL function L<BN_add_word|BN_add_word(3)>.

=item X<pre_inc>$new = ++$arg

Increments $arg by 1 inplace and returns that. $arg is first replaced by a
L<copy|"copy"> if there are other references to $arg.

This method is a wrapper for OpenSSL function L<BN_add_word|BN_add_word(3)>.

=item X<inc>$new = $arg->inc

Creates a new WEC::SSL::BigInt whose value is $arg plus one. This counts as
a unary operator, so it supports a $how argument which you can use to
change $arg inplace instead.

This method is a wrapper for OpenSSL function L<BN_add_word|BN_add_word(3)>.

=item X<inc_mutate>$new = $arg->inc_mutate

Increases $arg inplace and returns it. Basically the same as

  $new->inc(undef, undef);

This method is a wrapper for OpenSSL function L<BN_add_word|BN_add_word(3)>.

=item X<post_dec>$old = $arg--

$arg is replaced by a L<copy|"copy"> which then gets decremented inplace
(so it loses the exact type and becomes a WEC::SSL::BigInt unless you overrode
copy for your derived type). The old value of $arg before the copy is returned.

This method is a wrapper for OpenSSL function L<BN_sub_word|BN_sub_word(3)>.

=item X<pre_dec>$new = --$arg

Decrements $arg by 1 inplace and returns that. $arg is first replaced by a
L<copy|"copy"> if there are other references to $arg.

This method is a wrapper for OpenSSL function L<BN_sub_word|BN_sub_word(3)>.

=item X<dec>$new = $arg->dec

Creates a new WEC::SSL::BigInt whose value is $arg minus one. This counts as
a unary operator, so it supports a $how argument which you can use to
change $arg inplace instead.

This method is a wrapper for OpenSSL function L<BN_sub_word|BN_sub_word(3)>.

=item X<dec_mutate>$new = $arg->dec_mutate

Decreases $arg inplace and returns it. Basically the same as

  $new->dec(undef, undef);

This method is a wrapper for OpenSSL function L<BN_sub_word|BN_sub_word(3)>.

=item X<square>$square = $arg->square

Returns the argument squared. This method is not fundamentally faster than
$arg * $arg because L<multiply|"multiply"> detects the special case that the
two arguments refer to the same internal object and will then use the faster
internal square function.

         $arg   $square
  square(-12) = 144
  square( 12) = 144

This method is a wrapper for OpenSSL function L<BN_sqr|BN_set_sqr(3)>.

=item X<bit_length>$bits  = $arg->bit_length

Returns the number of bits needed to represent the absolute value of $arg.

Basically, for zero it returns 0, for all other values it returns
floor(log2(abs($arg)))+1.

This method is a wrapper for OpenSSL function L<BN_num_bits|BN_num_bits(3)> or
L<BN_num_bits_word|BN_num_bits_word(3)> if $arg is a small enough perl number.

=item X<byte_length>$bytes = $arg->byte_length

Returns the number of bytes needed to represent the absolute value of $arg.
This is basically ceil($arg->bit_length() / 8).

This method is a wrapper for OpenSSL function L<BN_num_bits|BN_num_bits(3)> or
L<BN_num_bits_word|BN_num_bits_word(3)> if $arg is a small enough perl number.

=item X<bit>$bit = $arg->bit($bit_nr)

Interprets $arg1 as a 2-complement bitstring and returns the value of bit
$bit_nr where the least significant bit is bit nr 0, the next nr 1 etc.
If $bit_nr is negative, bit -1 is the first bit different from the sign-bits,
-2 is the one to the right of that up to the number of bits. An even more
negative $bit_nr will raise an exception.

This method is a wrapper for for OpenSSL function
L<BN_is_bit_set|BN_is_bit_set(3)>.

=item $old_bit = $arg->bit($bit_nr, $new_bit)

Like L<bit|"bit">, but replaces the targeted bit by $new_bit while returning
the old bit-value.

This method modifies $arg1 inplace without making a copy, so it also changes
all aliases.

This method is a wrapper for for OpenSSL functions
L<BN_is_bit_set|BN_is_bit_set(3)>, L<BN_set_bit|BN_set_bit(3)> and
L<BN_clear_bit|BN_clear_bit(3)>.

=item X<abs_bit>$bit = $arg->abs_bit($bit_nr)

Like L<bit|"bit">, but only works on the absolute value of $arg.

This method modifies $arg1 inplace without making a copy, so it also changes
all aliases.

This method is a wrapper for for OpenSSL function
L<BN_is_bit_set|BN_is_bit_set(3)>.

=item $old_bit = $arg->abs_bit($bit_nr, $new_bit)

Like L<abs_bit|"abs_bit">, but replaces the targeted bit by $new_bit while
returning the old bit-value. The sign is kept.

This method is a wrapper for for OpenSSL functions
L<BN_is_bit_set|BN_is_bit_set(3)>, L<BN_set_bit|BN_set_bit(3)> and
L<BN_clear_bit|BN_clear_bit(3)>.

=item X<mask_bits>my $masked = mask_bits($arg, $bit_length)

Considers $arg as a 2-complement bitstring. If $bit_length is positive it
returns the $bit_length least significant bits (picking up sign bits as
needed). If $bit_length is negative, it returns the -$bit_length most
significant bits (starting at the first non-sign bit). If there are not
enough bits (for the negative $bit_length case), it raises an exception.

This method counts as a binary operator, so you can use a third $how
argument to reverse the order of arguments or to do the operation inplace
(which may be more efficient).

This method is a wrapper for for OpenSSL function
L<BN_mask_bits|BN_mask_bits(3)>.

=item X<abs_mask_bits>my $masked = abs_mask_bits($arg, $bit_length)

Does a L<mask_bits|"mask_bits"> on the absolute value of $arg and returns the
result with the original sign of $arg.

This method is a wrapper for for OpenSSL function
L<BN_mask_bits|BN_mask_bits(3)>.

=item X<sensitive>$sensitive = $arg->sensitive

=item $old_sensitive = $arg->sensitive($new_sensitive)

Every WEC::SSL::BigInt object has an associated sensitivity flag. When
called without argument the sensitive method returns a true value if this
flag is set, false otherwise. When called with an argument it makes the target
object sensitive if this value is true, non-sensitive otherwise. The
old sensitivity before the change is still returned.

Trying to turn sensitivity off using a sensitive (false) value will raise an
exception.

Notice that with a $new_sensitive argument this method changes sensitivity
in place, also changing it for all aliases.

Taintedness of $new_sensitive may or may not propagate to $arg.

When a new WEC::SSL::BigInt object is created, its flag will depend on the
sensitivity of the arguments of the operation that creates it. The result will
be sensitive if any of the arguments is sensitive, non-sensitive otherwise.
Pure perl values count as non-sensitive. So sensitivity propagation works in
essentially the same way as taint propagation.

The sensitivity flag is used whenever a WEC::SSL::BigInt object is destroyed.
If at that point the flag is set, the old value is cleared from memory by
overwriting its internal storage with zeros before freeing the memory.

The idea is that you set the sensitivity flags at the moment you store
a sensitive key into a variable, so that after that point you don't have to
worry what exactly happens to this key or the operations done on it, since
all derived values will also be sensitive and all of them will be zeroed when
they go out of scope. Notice however that unlike for tainting there is no
default where values are considered sensitive if they come from an external
source. It's up to the programmer to set the sensitivity flag when sensitive
data enters the system.

=item X<taint>$taint = $arg->taint

=item $old_taint = $arg->taint($new_taint)

A WEC::SSL::BigInt object is typically passed around as a reference to a perl
integer which in turn represents the address of a C object. Its the taintedness
of the perl integer that determines if the WEC::SSL::BigInt is tainted, but
naive use of the standard L<Scalar::Util tainted method|Scalar::Util/tainted>
method would test the reference instead.

To avoid this confusion this method is a combination of the dereference and
taint check of the perl integer. It returns a true value if that is tainted,
false otherwise.

When called with an argument, it taints (if the argument is true) or untaints
(if the argument is false) both the reference and the referenced perl integer.

Trying to turn tainting off using a tainted argument will result in an
exception.

The method returns the old tainting state of the referenced argument.

Notice that with a $new_tainted argument this method changes taintedness
in place, also changing it for all aliases (but for them the reference
will not get tainted).

Sensitivity of the argument may or may not propagate to the WEC::SSL::BigInt
object.

=item X<clear>$arg->clear

Sets $arg to zero, even erasing the internal unused memory in this variable.
Unsets the sensitivity bit and untaints the value too.

Clear is typically used to destroy sensitive data such as keys when they are
no longer needed.

You don't normally need to use this function explicitly if you set the
L<sensitivity flag|"sensitive"> for any sensitive data, since such values
will automatically get cleared when they are destroyed.

This method is a wrapper for for OpenSSL function L<BN_clear|BN_clear(3)>.

=item X<rand_prime>$prime = WEC::SSL::BigInt->rand_prime(%options)

Generates a $nr_bits (value of the mandatory L<bits|"rand_prime_bits">
option) pseudo-random prime number. The PRNG must have been seeded prior to
calling BN_generate_prime(). The prime number generation has a negligible error
probability.

Options are a sequence of name/value pairs giving details of the prime
number generation. They can be:

=over 4

=item X<rand_prime_bit_length>bit_length => $nr_bits

=item X<rand_prime_bits>bits => $nr_bits

A mandatory option specifying how many bits long the resulting prime should be.
Especially for small $nr_bits values there is a slight chance that the returned
value will be too large, in which case an exception will be raised (this is an
OpenSSL flaw that is still there in at least version 0.9.8).

=item X<rand_prime_modulus>modulus => $natural

=item X<rand_prime_mod>mod => $natural

=item X<rand_prime_m>m => $natural

If this option is given, the generated prime modulo $natural (an integer
greater than 0) should be 1 (or $remainder if that option is given too).

=item X<rand_prime_remainder>remainder => $integer

=item X<rand_prime_r>r => $integer

If this option is used, it must be combined with the
L<modulus|"rand_prime_modulus"> option. It means that the prime modulo the
$modulus should equal to $integer % $modulus. If this option is not given
it defaults to 1 if the L<modulus|"rand_prime_modulus"> option is given.

=item X<rand_prime_safe>safe => $bool

If this option is used with a true value, the generated prime must be a safe
one. That means that ($prime-1)/2 will be prime too.

=item X<rand_prime_callback>callback => $function_reference

This is a callback that will get called as follows just after each phase of
prime generation:

  $function_reference->($phase, $iteration)

where $phase designates what has just been done:

  0: Generated potential prime number $iteration
  1: Did Miller-Rabin probabilistic primality test number $iteration
  2: Found prime number $iteration

and $iteration gives the iteration number that was just done (starts counting
at 0). More arguments may be added in later versions of this module. If you
need extra private arguments, you can put them in the $function_reference
closure.

If an exception is thrown during the callback, the primality test is
immediately ended and the exception will be propagated. The internal
implicit block eval to make this work may however destroy the value $@ had
before the is_prime call.

=item X<rand_prime_callback_period>callback_period => $natural

If you don't want a (potentially slow) callback to happen after each test,
you can set this option. The callback will then only be called if $iteration
is a multiple of $natural.

=item X<rand_prime_sensitive>sensitive => $bool

Giving a true value means the result will be sensitive, giving a false value
means the result will not be sensitive and not giving this option means the
sensitivity of the result will depend on the sensitivity of the other option
values (except L<callback_period|rand_prime_callback_period>).

=back

The returned result is always tainted if the PRNG is not sufficiently seeded
(see L<WEC::SSL::Rand::status|WEC::SSL::Rand/status>).

This method is a wrapper for OpenSSL function
L<BN_generate_prime_ex|BN_generate_prime_ex(3)>.

=item X<prime>$bool = $arg->is_prime

Performs a Miller-Rabin probabilistic primality test on $arg. It runs enough
checks that the rate of false positives is at most 2**-80 for random input.
Returns true if $arg is prime, false otherwise. All integers below 2 count as
prime.

This method is a wrapper for OpenSSL function
L<BN_is_prime_fasttest_ex|BN_is_prime_fasttest_ex(3)>.

=item $bool = $arg->is_prime(%options)

The same as the above primality test, but with finer control of the testing
details. Options are a sequence of name/value pairs. These can be:

=over 4

=item X<is_prime_callback>callback => $function_reference

This is a callback that will get called as follows just after a test:

  $function_reference->($phase, $iteration)

where $phase designates what kind of test is being run:

  0: done test divisions
  1: done a Miller-Rabin probabilistic primality test

and $iteration gives the iteration number that was just done (starts counting
at 0). More arguments may be added in later versions of this module. If you
need extra private arguments, you can put them in the $function_reference
closure.

If an exception is thrown during the callback, the primality test is
immediately ended and the exception will be propagated. The internal
implicit block eval to make this work may however destroy the value $@ had
before the is_prime call.

=item X<is_prime_callback_period>callback_period => $natural

If you don't want a (potentially slow) callback to happen after each test,
you can set this option. The callback will then only be called if $iteration
is a multiple of $natural.

=item X<is_prime_checks>checks => $natural

This indicates how many Miller-Rabin probabilistic primality tests have to be
done. If $natural is the special value undef, it internally uses a value such
that the rate of false positives is at most 2**-80 for random input.

=item X<is_prime_trial_divisions>trial_divisions => $bool

If and only if this option is given with a true value, it will first attempt
trial divisions by a number of small primes before doing the probabilistic
tests.

=back

This method is a wrapper for OpenSSL function
L<BN_is_prime_fasttest_ex|BN_is_prime_fasttest_ex(3)>.

=item X<rand>$rand = $limit->rand

$limit should be an integer greater than zero (otherwise an exception is
raised). The returned value will be a cryptographically strong pseudo-random
number in the range 0 E<lt>= $rand E<lt> $limit.

The PRNG must be seeded prior to calling this method.

The returned result is always tainted if the PRNG is not sufficiently seeded
(see L<WEC::SSL::Rand::status|WEC::SSL::Rand/status>).

This method is a wrapper for OpenSSL function
L<BN_rand_range|BN_rand_range(3)>.

=item X<pseudo_rand>$rand = $limit->pseudo_rand

$limit should be an integer greater than zero (otherwise an exception is
raised). The returned value will be a pseudo-random number in the range
0 E<lt>= $rand E<lt> $limit. The result can be used for non-cryptographic
purposes and for certain purposes in cryptographic protocols, but usually not
for key generation etc.

The returned result is always tainted if the PRNG is not sufficiently seeded
(see L<WEC::SSL::Rand::status|WEC::SSL::Rand/status>).

This method is a wrapper for OpenSSL function
L<BN_pseudo_rand_range|BN_pseudo_rand_range(3)>.

=item X<rand_bits>$rand = WEC::SSL::BigInt->rand_bits(%options)

This method returns a cryptographically strong pseudo-random number.

=over 4

=item X<rand_bits_bits>bits => $nr_bits

=item X<rand_bits_bit_length>bit_length => $nr_bits

A mandatory option specifying how many bits long the resulting random number
should be.

=item X<rand_bits_lsb_ones>lsb_ones => $zero_or_one

How many ones there will be at the least significant side of the result.
Asking for 1 basically means the result will be odd.

=item X<rand_bits_msb_ones>msb_ones => $zero_one_or_two

How many ones there will be at the most significant side of the result.
So specifying 0 here means the result can be shorter than $nr_bits. It will be
exactly $nr_bits otherwise. Specifying 2 means the two most significant bits
will be one, which implies that the product of two such numbers will have
bit_length 2*$nr_bits.

=item X<rand_bits_sensitive>sensitive => $bool

Giving a true value means the result will be sensitive, giving a false value
means the result will not be sensitive and not giving this option means the
sensitivity of the result will depend on the sensitivity of the other option
values.

=back

The PRNG must be seeded prior to calling this method.

The returned result is always tainted if the PRNG is not sufficiently seeded
(see L<WEC::SSL::Rand::status|WEC::SSL::Rand/status>).

This method is a wrapper for OpenSSL function L<BN_rand|BN_rand(3)>.

=item X<pseudo_rand_bits>$rand = WEC::SSL::BigInt->pseudo_rand_bits(%options)

This method returns a pseudo-random number. It can be used for
non-cryptographic purposes and for certain purposes in cryptographic protocols,
but usually not for key generation etc.

=over 4

=item X<pseudo_rand_bits_bits>bits => $nr_bits

=item X<rand_bits_bit_length>bit_length => $nr_bits

A mandatory option specifying how many bits long the resulting random number
should be.

=item X<pseudo_rand_bits_lsb_ones>lsb_ones => $zero_or_one

How many ones there will be at the least significant side of the result.
Asking for 1 basically means the result will be odd.

=item X<pseudo_rand_bits_msb_ones>msb_ones => $zero_one_or_two

How many ones there will be at the most significant side of the result.
So specifying 0 here means the result can be shorter than $nr_bits. It will be
exactly $nr_bits otherwise. Specifying 2 means the two most significant bits
will be one, which implies that the product of two such numbers will have
bit_length 2*$nr_bits.

=item X<pseudo_rand_bits_sensitive>sensitive => $bool

Giving a true value means the result will be sensitive, giving a false value
means the result will not be sensitive and not giving this option means the
sensitivity of the result will depend on the sensitivity of the other option
values.

=back

The returned result is always tainted if the PRNG is not sufficiently seeded
(see L<WEC::SSL::Rand::status|WEC::SSL::Rand/status>).

This method is a wrapper for OpenSSL function
L<BN_pseudo_rand|BN_pseudo_rand(3)>.

=item X<print>$printed = $val->print

=item  $printed = $val->print($fh)

This is a convenience method which is basically equivalent to

  $printed = print $val->to_decimal
  $printed = print $fh $val->to_decimal

except that when $fh is a string, it's tracked back into the caller chain until
it refers to an open filedescriptor.

=item X<print_hex>$printed = $val->print_hex

=item $printed = $val->print_hex($fh)

This is a convenience method which is basically equivalent to

  $printed = print $val->to_hex
  $printed = print $fh $val->to_hex

except that when $fh is a string, it's tracked back into the caller chain until
it refers to an open filedescriptor.

=item X<print_HEX>$printed = $val->print_HEX

=item $printed = $val->print_HEX($fh)

This is a convenience method which is basically equivalent to

  $printed = print $val->to_HEX
  $printed = print $fh $val->to_HEX

except that when $fh is a string, it's tracked back into the caller chain until
it refers to an open filedescriptor.

This method is the perl equivalent of what OpenSSL function
L<BN_print_fp|BN_print_fp(3)> would do, but doesn't actually use that function.

=item X<bio_print_HEX>$printed = $val->bio_print_HEX($bio)

Writes $val->to_HEX(1) to bio $bio.

This method is a wrapper for OpenSSL function L<BN_print|BN_print(3)>

=back

=head1 EXPORTS

Except for the constructors everything is exportable, but nothing is exported
by default. It uses L<Exporter::Tidy|Exporter::Tidy> for the exports, so
you can import methods under modified (prefixed) names.

=head1 SEE ALSO

L<WEC::SSL::Errors>,
L<WEC::SSL::Reciprocal>,
L<WEC::SSL::Montgomery>

=head1 AUTHOR

Ton Hospel, E<lt>WEC-SSL-BigInt@ton.iguana.beE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.6.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
