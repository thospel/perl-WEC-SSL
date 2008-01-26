#!/usr/bin/perl -w

~0 == 18446744073709551615 || die "Only run this on a 64-bit perl";

sub bits {
    my $num = shift;
    $num = -$num-1 if $num < 0;
    return 0 if $num == 0;
    my $bits = 0;
    while ($num) {
        $bits++;
        $num >>= 1;
    }
    return $bits;
}

sub get_bit {
    my ($num, $bit) = @_;
    if ($bit < 0) {
        $bit = bits($num)+$bit;
        die "literal: Bitnumber too negative" if $bit < 0;
    }
    return ($num & 1 << $bit) ? 1 : 0;
}

my %tests = (add	=> [10, "binary", "+"],
             subtract	=> [11, "binary", "-"],
             multiply	=> [12, "binary", "*"],
             quotient	=> [13, "binary", "/", "div by zero"],
             divide	=> [13, "binary", sub { shift() / shift }, "div by zero"],
             perl_divide=> [13, "binary", sub { shift() / shift }, "div by zero"],
             modulo	=> [14, "binary", "%", "div by zero"],
             perl_modulo=> [14, "binary", sub { shift() % shift }, "div by zero"],
             remainder	=> [14, "binary", sub {
                 use integer;
                 return shift() % shift;
             }, "div by zero"],
             perl_remainder	=> [14, "binary", sub {
                 use integer;
                 return shift() % shift;
             }, "div by zero"],
             abs_remainder => [14, "binary", sub {
                 return shift() % abs(shift);
             }, "div by zero"],
             perl_abs_remainder => [14, "binary", sub {
                 return shift() % abs(shift);
             }, "div by zero"],
             pow	=> [15, "binary", "**", "Negative exponent not supported"],
             and	=> [16, "binary", "&"],
             or		=> [17, "binary", "|"],
             xor	=> [18, "binary", "^"],
             lshift	=> [19, "binary", "<<"],
             rshift	=> [20, "binary", ">>"],
             gcd	=> [21, "binary", sub {
                 my $a = abs shift;
                 my $b = abs shift;
                 $a || $b || die "literal: gcd(0, 0) is undefined";
                 while ($b) {
                     ($a, $b) = ($b, $a % $b);
                 }
                 return $a;
             }],
             mod_inverse => [22, "binary", sub {
                 my $times = shift;
                 my $modulus = abs shift;
                 die "literal: div by zero" if $modulus == 0;
                 return 0 if $modulus == 1;
                 for my $i (0..$modulus-1) {
                     return $i if $i * $times % $modulus == 1;
                 }
                 die "literal: no inverse";
             }],
             mod_square => [23, "binary", sub {
                 my $times = shift;
                 my $modulus = abs shift;
                 die "literal: div by zero" if $modulus == 0;
                 return $times*$times % $modulus;
             }],
             cmp	=> [30, "binary", "<=>"],
             abs_cmp	=> [30, "binary", sub {abs(shift) <=> abs(shift)} ],
             eq		=> [31, "binary", "==" ],
             ne		=> [31, "binary", "!=" ],
             lt		=> [32, "binary", "<"  ],
             le		=> [33, "binary", "<=" ],
             gt		=> [34, "binary", ">"  ],
             ge		=> [35, "binary", ">=" ],
             copy_sign	=> [39, "binary", sub {
                 $_[1] == 0 ? 0 : $_[1] < 0 ? -abs shift : abs shift;
             }],
             negate	=> [40, "unary", "-"],
             complement	=> [41, "unary", "~"],
             # inc	=> [42, "unary", "++"],
             # dec	=> [43, "unary", "--"],
             lshift1	=> [44, "unary", sub {
                 use integer;
                 return shift() << 1;
             }],
             rshift1	=> [44, "unary", sub {
                 use integer;
                 return shift() >> 1;
             }],
             abs	=> [45, "unary", "abs"],
             abs_to_integer	=> [45, "unary", sub { return abs shift }],
             perl_abs	=> [45, "unary", sub { return abs shift }],
             square	=> [46, "unary", sub { return shift() ** 2 }],
             int	=> [47, "unary", sub { return shift }],
             to_integer	=> [47, "unary", sub { return shift }],
             perl_int	=> [47, "unary", sub { return shift }],
             sign	=> [48, "unary", sub { shift() <=> 0 }],
             is_zero	=> [48, "unary", "!"],
             is_non_zero=> [48, "unary", sub { return shift != 0}],
             is_one	=> [48, "unary", sub { return shift == 1}],
             is_even	=> [49, "unary", sub { return shift() % 2 == 0}],
             is_odd	=> [49, "unary", sub { return shift() % 2 != 0}],
             # bit	=> [62, "binary", sub { return get_bit(shift, shift)}],
             # abs_bit	=> [62, "binary", sub {
             #    my $num = shift;
             #    return $num < 0 ?
             #        get_bit(-$num, shift) :
             #        get_bit($num, shift);
             #}],
             mask_bits	=> [63, "binary", sub {
                 use integer;
                 my ($num, $bits) = @_;
                 if ($bits < 0) {
                     my $shift = bits($num) + $bits;
                     die "literal: Bits too negative" if $shift < 0;
                     $num >>= $shift;
                     $bits = -$bits;
                 }
                 return $num & (1 << $bits) - 1;
             }],
             abs_mask_bits => [63, "binary", sub {
                 my ($num, $bits) = @_;
                 my $n = abs $num;
                 if ($bits < 0) {
                     my $shift = bits($n) + $bits;
                     die "literal: Bits too negative" if $shift < 0;
                     $n >>= $shift;
                     $bits = -$bits;
                 }
                 $n = $n &  (1 << $bits) - 1;
                 return $num < 0 ? -$n : $n;
             }],
             );

my $template = do { local $/; <DATA> };
close DATA;

for my $name (sort { $tests{$a}[0] <=> $tests{$b}[0] } keys %tests) {
    my $num   = $tests{$name}[0];
    my $ary   = $tests{$name}[1];
    my $op    = $tests{$name}[2];
    my $error = $tests{$name}[3] || "no error expected";

    my $result = $template;
    $result =~ s/\$NAME/$name/g;
    $result =~ s/\$NUM/sprintf("%03d", $num)/eg;
    if ($ary eq "binary") {
        $result =~ s/DECLARE/my (\$arg1, \$arg2, \$tmp, \$result, \$MORE_ARGS)/g;
        $result =~ s/BINARY\s*\(\s*([^,\)]+),\s*([^,\)]+)\)/bin_op($op, $name, $error, $1, $2)/eg;
    } else {
        $result =~ s/BINARY\s*\(\s*[^,\)]+,\s*[^,\)]+\)//g;
    }
    if ($ary eq "unary") {
        $result =~ s/DECLARE/my (\$arg, \$tmp, \$result)/g;
        $result =~ s/UNARY\s*\(\s*([^\)]+)\)/un_op($op, $name, $error, $1)/eg;
    } else {
        $result =~ s/UNARY\s*\(\s*[^\)]+\)//g;
    }
    $result =~ s/,\s*\$MORE_ARGS/$name =~ m!divide! ? ", \$q, \$r" : ""/eg;

    my $file = sprintf("%03d_%s.t", $num, $name);
    my $new = "$file.new.$$";
    open(my $fh, ">", $new) || die "Could not open $new: $!";
    eval {
        print($fh $result) || die "Error writing to $new: $!";
        close($fh) || die "Error closing $new: $!";
        rename($new, $file) || die "Could not rename $new to $file: $!";
    };
    if ($@) {
        $fh = undef;
        unlink($new) || die "Could not unlink $new: $!";
        die $@;
    }
}

sub bin_op {
    my ($op, $name, $error, $arg1, $arg2) = @_;

    my $eval = "";
    if ($name eq "and" || $name eq "or" || $name eq "xor" ||
        $name eq "lshift" || $name eq "rshift") {
        $eval .= "use integer;";
    }
    if ($name eq "lshift" && $arg2 < 0) {
        my $tmp = -$arg2;
        $eval .= "($arg1) >> ($tmp)";
    } elsif ($name eq "rshift" && $arg2 < 0) {
        my $tmp = -$arg2;
        $eval .= "($arg1) << ($tmp)";
    } elsif (ref($op)) {
        $eval .= "\$op->($arg1, $arg2)";
    } else {
        $eval .= "($arg1) $op ($arg2)";
    }
    # print STDERR "$eval\n";
    my $result = eval $eval;
    my $string;
    if ($@ || $name eq "pow" && $arg2 < 0) {
        $error = $1 if $@ =~ /^literal: (.*) at \Q$0/;
        $string = <<"EOF";
# $name($arg1, $arg2) fails
\$arg1 = Big->new($arg1);
\$arg2 = Big->new($arg2);

\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

\$result = eval { WEC::SSL::BigInt::$name(\$arg2, \$arg1, 1) };
like(\$@, qr/\\Q$error/i);

\$tmp = \$arg1->copy;
\$result = eval { WEC::SSL::BigInt::$name(\$tmp, \$arg2, undef) };
like(\$@, qr/\\Q$error/i);
is("\$arg1", $arg1);

\$result = eval { WEC::SSL::BigInt::$name($arg1, $arg2) };
like(\$@, qr/\\Q$error/i);

\$result = eval { \$arg1->$name(\$arg2) };
like(\$@, qr/\\Q$error/i);

\$result = eval { \$arg1->$name($arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
\$result = eval { \$arg1 $op \$arg2 };
like(\$@, qr/\\Q$error/i);

\$result = eval { \$arg1 $op $arg2 };
like(\$@, qr/\\Q$error/i);

\$result = eval { $arg1 $op \$arg2 };
like(\$@, qr/\\Q$error/i);

<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= $arg2 };
like(\$@, qr/\\Q$error/i);
is("\$arg1", $arg1);

\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
is("\$arg1", $arg1);
<OP=_END>
<OP_END>

# Check sensitive propagation
\$arg1->sensitive(1);
\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
ok(\$tmp->sensitive);
<OP=_END>
<OP_END>

\$arg2->sensitive(1);
\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
ok(\$tmp->sensitive);
<OP=_END>
<OP_END>

\$arg1->sensitive(0);
\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
ok(!\$tmp->sensitive);
<OP=_END>
<OP_END>

\$arg2->sensitive(0);
\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
ok(!\$tmp->sensitive);
<OP=_END>
<OP_END>

<TAINT_START>
# Check taint propagation
\$arg1->tainted(1);
\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
ok(tainted(\$tmp));
<OP=_END>
<OP_END>

\$arg2->tainted(1);
\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
ok(tainted(\$tmp));
<OP=_END>
<OP_END>

\$arg1->tainted(0);
\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
ok(!tainted(\$tmp));
<OP=_END>
<OP_END>

\$arg2->tainted(0);
\$result = eval { WEC::SSL::BigInt::$name(\$arg1, \$arg2) };
like(\$@, qr/\\Q$error/i);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
eval { \$tmp $op= \$arg2 };
like(\$@, qr/\\Q$error/i);
ok(!tainted(\$tmp));
<OP=_END>
<OP_END>
<TAINT_END>

EOF
    } else {
        if (defined $result) {
            if ($result eq "") {
                $result = qq("");
            } elsif ($result == 9**9**9) {
                $result = "9**9**9";
            } else {
                $result = int $result;

            }
        } else {
            $result = undef;
        }
        $string = <<"EOF";
# $name($arg1, $arg2) = $result
\$arg1 = Big->new($arg1);
\$arg2 = Big->new($arg2);

\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$result = WEC::SSL::BigInt::$name(\$arg2, \$arg1, 1);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$tmp = \$arg1->copy;
\$result = WEC::SSL::BigInt::$name(\$tmp, \$arg2, undef);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>
<ALIAS_START>
isa_ok(\$tmp, "WEC::SSL::BigInt");
<ALIAS_END>
is("\$arg1", $arg1);

\$result = WEC::SSL::BigInt::$name($arg1, $arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$result = \$arg1->$name(\$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$result = \$arg1->$name($arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

<OP_START>
\$result = \$arg1 $op \$arg2;
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$result = \$arg1 $op $arg2;
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$result = $arg1 $op \$arg2;
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

<OP=_START>
\$tmp = \$arg1;
\$tmp $op= $arg2;
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$tmp", $result);
ok(!\$tmp->sensitive);
<TAINT_START>
ok(!tainted(\$tmp));
<TAINT_END>
is("\$arg1", $arg1);

\$tmp = \$arg1;
\$tmp $op= \$arg2;
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$tmp", $result);
ok(!\$tmp->sensitive);
<TAINT_START>
ok(!tainted(\$tmp));
<TAINT_END>
is("\$arg1", $arg1);
<OP=_END>
<OP_END>

# Check sensitive propagation
\$arg1->sensitive(1);
\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(\$result->sensitive);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
\$tmp $op= \$arg2;
ok(\$tmp->sensitive);
<OP=_END>
<OP_END>

\$arg2->sensitive(1);
\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(\$result->sensitive);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
\$tmp $op= \$arg2;
ok(\$tmp->sensitive);
<OP=_END>
<OP_END>

\$arg1->sensitive(0);
\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(\$result->sensitive);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
\$tmp $op= \$arg2;
ok(\$tmp->sensitive);
<OP=_END>
<OP_END>

\$arg2->sensitive(0);
\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);

<OP_START>
<OP=_START>
\$tmp = \$arg1;
\$tmp $op= \$arg2;
ok(!\$tmp->sensitive);
<OP=_END>
<OP_END>

<TAINT_START>
# Check taint propagation
\$arg1->tainted(1);
\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(tainted(\$result));

<OP_START>
<OP=_START>
\$tmp = \$arg1;
\$tmp $op= \$arg2;
ok(tainted(\$tmp));
<OP=_END>
<OP_END>

\$arg2->tainted(1);
\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(tainted(\$result));

<OP_START>
<OP=_START>
\$tmp = \$arg1;
\$tmp $op= \$arg2;
ok(tainted(\$tmp));
<OP=_END>
<OP_END>

\$arg1->tainted(0);
\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(tainted(\$result));

<OP_START>
<OP=_START>
\$tmp = \$arg1;
\$tmp $op= \$arg2;
ok(tainted(\$tmp));
<OP=_END>
<OP_END>

\$arg2->tainted(0);
\$result = WEC::SSL::BigInt::$name(\$arg1, \$arg2);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!tainted(\$result));

<OP_START>
<OP=_START>
\$tmp = \$arg1;
\$tmp $op= \$arg2;
ok(!tainted(\$tmp));
<OP=_END>
<OP_END>
<TAINT_END>

EOF
    }
    if (ref($op)) {
        $string =~ s/<OP_START>\s*\n(.*?)<OP_END>\s*\n//sg;
    } else {
        $string =~ s/<OP_START>\s*\n(.*?)<OP_END>\s*\n/$1/sg;
    }
    if ($op eq "==" || $op eq "!=" ||
        $op eq "<" || $op eq "<=" || $op eq ">" || $op eq ">=") {
        $string =~ s/<TAINT_START>\s*\n(.*?)<TAINT_END>\s*\n//sg;
    } else {
        $string =~ s/<TAINT_START>\s*\n(.*?)<TAINT_END>\s*\n/$1/sg;
    }
    if ($name eq "abs_cmp" || ($name =~ /^perl_/ && $name ne "perl_divide") ||
        $op eq "<=>" || $op eq "==" || $op eq "!=" ||
        $op eq "<" || $op eq "<=" || $op eq ">" || $op eq ">=") {
        $string =~ s/<OP=_START>\s*\n(.*?)<OP=_END>\s*\n//sg;
        $string =~ s/<ALIAS_START>\s*\n(.*?)<ALIAS_END>\s*\n//sg;
        $string =~ s/isa_ok\(\$result,.*/is(ref(\$result), "");/g;
        $string =~ s/is\("\$result",/is\(\$result,/g;
        $string =~ s/# Check sensitive propagation/# Check operation under sensitivity/g;
        $string =~ s/ok\(.*sensitive.*\n//g;
    } else {
        $string =~ s/<OP=_START>\s*\n(.*?)<OP=_END>\s*\n/$1/sg;
        $string =~ s/<ALIAS_START>\s*\n(.*?)<ALIAS_END>\s*\n/$1/sg;
    }
    # Fix for the fact that -a ** b is - (a ** b) while we mean (-a) ** b
    $string =~ s/(-\s*\d+)(\s*\*\*)/($1)$2/g;

    if ($name =~ /divide/) {
        # Do the same thing again, but now returning both q and r
        my $new_string = $string;
        $new_string =~ s/\$result = /(\$q, \$r) = /g;
        $new_string =~ s/(.*)\$result(.*)/$1\$q$2\n$1\$r$2/g;
        if ($name =~/perl|bit/) {
            $new_string =~ s/isa_ok\(\$r,.*/is(ref(\$r), "");/g;
            $new_string =~ s/^\s*ok\(.*\$r->sensitive.*\n//mg;
        }
        my $r;
        $new_string =~ s{\#\s*\Q$name\E\s*\(\s*(-?\d+)\s*,\s*(-?\d+)\s*\)\s*(.*)|is\("\$r",\s*(-?\d+)\)}{
            if (defined $1) {
                if ($3 eq "fails") {
                    "# $name($1, $2) fails";
                } else {
                    my $a = $1;
                    my $b = $2;
                    $3 =~ /\s*=\s*(-?\d+)/ || die "No num in $3";
                    $r = $a - $b * $1;
                    "# $name($a, $b) = ($1, $r)";
                }
            } else {
                qq(is("\$r", $r));
            }
        }eg;
        $string .= $new_string;
    }
    # Quote very big results
    $string =~ s/(is\s*\([^,]+,\s*)(-?\d+)(\s*\);)/abs($2) >= 2**31 ? qq($1"$2"$3) : "$1$2$3"/eg;
    return $string;
}

sub un_op {
    my ($op, $name, $error, $arg) = @_;

    my $eval = "";
    if ($name eq "complement") {
        $eval .= "use integer;";
    }
    if (ref($op)) {
        $eval .= "\$op->($arg)";
    } else {
        $eval .= " $op ($arg)";
    }
    # print STDERR "$eval\n";
    my $result = eval $eval;
    my $string;
    if ($@) {
        $error = $1 if $@ =~ /^literal: (.*) at \Q$0/;
        $string = <<"EOF";
# $name($arg) fails
\$arg = Big->new($arg);

\$result = eval { WEC::SSL::BigInt::$name(\$arg) };
like(\$@, qr/\\Q$error/i);

\$result = eval { WEC::SSL::BigInt::$name(\$arg, undef, 1) };
like(\$@, qr/\\Q$error/i);

\$tmp = \$arg->copy;
\$result = eval { WEC::SSL::BigInt::$name(\$tmp, undef, undef) };
like(\$@, qr/\\Q$error/i);
is("\$arg", $arg);

\$result = eval { WEC::SSL::BigInt::$name($arg) };
like(\$@, qr/\\Q$error/i);

\$result = eval { \$arg->$name };
like(\$@, qr/\\Q$error/i);

<OP_START>
\$result = eval { $op \$arg };
like(\$@, qr/\\Q$error/i);
<OP_END>

# Check sensitive propagation
\$arg->sensitive(1);
\$result = eval { WEC::SSL::BigInt::$name(\$arg) };
like(\$@, qr/\\Q$error/i);

<OP_START>
\$result = eval { $op \$arg };
like(\$@, qr/\\Q$error/i);
ok(\$arg->sensitive);
<OP_END>

\$arg->sensitive(0);
\$result = eval { WEC::SSL::BigInt::$name(\$arg) };
like(\$@, qr/\\Q$error/i);

<OP_START>
\$result = eval { $op \$arg };
like(\$@, qr/\\Q$error/i);
ok(!\$arg->sensitive);
<OP_END>

<TAINT_START>
# Check taint propagation
\$arg->tainted(1);
\$result = eval { WEC::SSL::BigInt::$name(\$arg) };
like(\$@, qr/\\Q$error/i);

<OP_START>
\$result = eval { $op \$arg };
like(\$@, qr/\\Q$error/i);
ok(tainted(\$arg));
<OP_END>

\$arg->tainted(0);
\$result = eval { WEC::SSL::BigInt::$name(\$arg) };
like(\$@, qr/\\Q$error/i);

<OP_START>
\$result = eval { $op \$arg };
like(\$@, qr/\\Q$error/i);
ok(!tainted(\$arg));
<OP_END>
<TAINT_END>

EOF
    } else {
        if (defined $result) {
            if ($result eq "") {
                $result = qq("");
            } elsif ($result == 9**9**9) {
                $result = "9**9**9";
            } else {
                $result = int $result;

            }
        } else {
            $result = undef;
        }
        $string = <<"EOF";
# $name($arg) = $result
\$arg = Big->new($arg);

\$result = WEC::SSL::BigInt::$name(\$arg);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$result = WEC::SSL::BigInt::$name(\$arg, undef, 1);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$tmp = \$arg->copy;
\$result = WEC::SSL::BigInt::$name(\$tmp, undef, undef);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>
<ALIAS_START>
isa_ok(\$tmp, "WEC::SSL::BigInt");
<ALIAS_END>
is("\$arg", $arg);

\$result = WEC::SSL::BigInt::$name($arg);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

\$result = \$arg->$name;
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>

<OP_START>
\$result = $op \$arg;
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);
<TAINT_START>
ok(!tainted(\$result));
<TAINT_END>
<OP_END>

# Check sensitive propagation
\$arg->sensitive(1);
\$result = WEC::SSL::BigInt::$name(\$arg);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(\$result->sensitive);

<OP_START>
\$result = $op \$arg;
ok(\$result->sensitive);
is("\$result", $result);
<OP_END>

\$arg->sensitive(0);
\$result = WEC::SSL::BigInt::$name(\$arg);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!\$result->sensitive);

<OP_START>
\$result = $op \$arg;
ok(!\$result->sensitive);
is("\$result", $result);
<OP_END>

<TAINT_START>
# Check taint propagation
\$arg->tainted(1);
\$result = WEC::SSL::BigInt::$name(\$arg);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(tainted(\$result));

<OP_START>
\$result = $op \$arg;
ok(tainted(\$result));
<OP_END>

\$arg->tainted(0);
\$result = WEC::SSL::BigInt::$name(\$arg);
isa_ok(\$result, "WEC::SSL::BigInt");
is("\$result", $result);
ok(!tainted(\$result));

<OP_START>
\$result = $op \$arg;
ok(!tainted(\$result));
<OP_END>
<TAINT_END>

EOF
    }
    if (ref($op)) {
        $string =~ s/<OP_START>\s*\n(.*?)<OP_END>\s*\n//sg;
    } else {
        $string =~ s/<OP_START>\s*\n(.*?)<OP_END>\s*\n/$1/sg;
    }
    if ($name =~ /^is_/) {
        $string =~ s/<TAINT_START>\s*\n(.*?)<TAINT_END>\s*\n//sg;
    } else {
        $string =~ s/<TAINT_START>\s*\n(.*?)<TAINT_END>\s*\n/$1/sg;
    }
    if ($name =~ /^perl_|^is_|^sign|to_integer/) {
        $string =~ s/<OP=_START>\s*\n(.*?)<OP=_END>\s*\n//sg;
        $string =~ s/isa_ok\(\$result,.*/is(ref(\$result), "");/g;
        $string =~ s/is\("\$result",/is\(\$result,/g;
        $string =~ s/# Check sensitive propagation/# Check operation under sensitivity/g;
        $string =~ s/ok\(.*sensitive.*\n//g;
    } else {
        $string =~ s/<OP=_START>\s*\n(.*?)<OP=_END>\s*\n/$1/sg;
    }
    if ($name =~ /^perl_|to_integer/) {
        $string =~ s/<ALIAS_START>\s*\n(.*?)<ALIAS_END>\s*\n//sg;
    } else {
        $string =~ s/<ALIAS_START>\s*\n(.*?)<ALIAS_END>\s*\n/$1/sg;
    }
    # Quote very big results
    $string =~ s/(is\s*\([^,]+,\s*)(-?\d+)(\s*\);)/abs($2) >= 2**31 ? qq($1"$2"$3) : "$1$2$3"/eg;
    return $string;
}

__DATA__
#!/usr/bin/perl -wT
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl -T $NUM_$NAME.t'

use strict;
use warnings;
use Scalar::Util qw(tainted);
BEGIN { $^W = 1 };
use Test::More "no_plan";

BEGIN { use_ok("WEC::SSL::BigInt") };

{
    package Big;
    our @ISA = qw(WEC::SSL::BigInt);
}

my @methods = qw($NAME);
can_ok("WEC::SSL::BigInt", @methods);
for my $method (@methods) {
    next if ! __PACKAGE__->can($method);
    fail("$method seems to be force exported");
}

DECLARE;

BINARY(-1,-1)
BINARY(-1,0)
BINARY(-1,1)
BINARY(0,-1)
BINARY(0,0)
BINARY(0,1)
BINARY(1,-1)
BINARY(1,0)
BINARY(1,1)
BINARY(12,9)
BINARY(-12,9)
BINARY(12,-9)
BINARY(-12,-9)
BINARY(581,3)
BINARY(581,-3)
BINARY(-581,3)
BINARY(-581,-3)

UNARY(-3)
UNARY(-2)
UNARY(-1)
UNARY(0)
UNARY(1)
UNARY(2)
UNARY(3)
UNARY(9)
UNARY(-9)
UNARY(12)
UNARY(-12)
UNARY(581)
UNARY(-581)

"WEC::SSL::BigInt"->import(@methods);
can_ok(__PACKAGE__, @methods);
