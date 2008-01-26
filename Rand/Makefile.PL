#!/usr/bin/perl -w
# $Id: Makefile.PL 2693 2008-01-02 09:54:19Z hospelt $
use 5.006001;
use strict;
use warnings;
use ExtUtils::MakeMaker;
use vars qw($VERSION);
$VERSION = "1.000";

# Path testing derived from Net::SSLeay
my $openssl_path;
# Maybe hunt for a specific recent enough version...
for my $dir (split /:/, $ENV{PATH}) {
    if (-f "$dir/openssl" && -x _ || -f "$dir/openssl.exe" && -x _) {
        $dir =~ s!/s?bin/*\z!!;
        $openssl_path = $dir;
        last;
    }
}
$openssl_path = shift if @ARGV && $ARGV[0] ne "--";
shift if @ARGV && $ARGV[0] eq '--';   # Rest of args are for MakeMaker

die "Could not find openssl executable\n" if !$openssl_path;
print "openssl_path=$openssl_path\n";
my $exe_path;
for my $exe_name ("bin/openssl", "bin/openssl.exe",
                  "sbin/openssl", "sbin/openssl.exe",
                  "out32dll/openssl.exe",
                  "openssl", "openssl.exe") {
    if (-f "$openssl_path/$exe_name" && -x _) {
        $exe_path = "$openssl_path/$exe_name";
        last;
    }
}
if (!$exe_path) {
    die "I could not find your OpenSSL in '$openssl_path'\n";
}
print "exe_path=$exe_path\n";

my $version = `$exe_path version` ||
    die "Couldn't run '$exe_path version' ($?)\n";
my ($lib_name, $major, $minor, $letters) =
    $version =~ /^(OpenSSL)\s+(\d+\.\d+)\.(\d+)([a-z-]*)\s/ or
    die("Could not parse OpenSSL version string '$version'.\n",
        "Either you have bogus OpenSSL or a new version has changed the version number format.\n");
print "version is $lib_name $major.$minor$letters\n";

my ($libs, $rsaref);
if ($^O eq "MSWin32") {
    warn "RSAREF build on Windows not supported out of box" if $rsaref;
    $libs = "-llibeay32 -lssleay32";
} else {
    # There is some confusion over the correct ordering
    # of these libraries. Tarang Kumar Patel <mombasa@ptolemy.arc.nasa.gov>
    # reports this order to work on Solaris 7 and openssl-0.9.6b
    $libs = $rsaref ? "-lssl -lcrypto -lRSAglue -lrsaref" : "-lssl -lcrypto";

    # old order which might work on some platforms
    #$libs = $rsaref ? "-lssl -lRSAglue -lcrypto -lrsaref" : "-lssl -lcrypto";

    # Check that perl and openssl were compiled using the same compiler
    # and options.

    # When using aCC under HP-UX additional `+e' flag must be passed.
    # --code not implemented--
}

WriteMakefile
    (NAME		=> 'WEC::SSL::Rand',
     VERSION_FROM	=> 'lib/WEC/SSL/Rand.pm', # finds $VERSION
     PREREQ_PM		=> {
         "Exporter::Tidy"	=> 0.05,	# For flexible exporting"
         "Test::More"		=> 0.11,	# For the tests only
     }, # e.g., Module::Name => 1.1
     ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (AUTHOR		=> 'Ton Hospel <WEC-SSL-Rand@ton.iguana.be>') : ()),
     # OPTIMIZE		=> "-g",
     LIBS		=> ["-L$openssl_path -L$openssl_path/lib -L$openssl_path/out32dll $libs"],
     INC 		=> "-I ../include -I$openssl_path/include -I$openssl_path/inc32",
     DEFINE		=> '', # e.g., '-DHAVE_SOMETHING'
     # Un-comment this if you add C files to link with later:
     # OBJECT		=> '$(O_FILES)',
     $^O eq "MSWin32" ? (
         PM_FILTER	=> '$(PERL) -p -e1',
     ) : (),
     clean		=> {
         FILES => '$(DISTVNAME).ppm',
     },
);

package MY;
sub postamble {
    return shift->SUPER::postamble() . <<"EOF";
ppm: \$(DISTVNAME).ppm

\$(DISTVNAME).ppm: all ppd
	makeppd.pl --perl=\$(PERL) --min_version=1.011 --zip=\$(ZIP) --tar=\$(TAR) --compress="\$(COMPRESS)" --leave=ppm \$(DISTNAME).ppd \$(VERSION)

ppm_install: \$(DISTVNAME).ppm
	ppm install ppm/\$(DISTNAME).ppd

ppm_upgrade: \$(DISTVNAME).ppm
	ppm upgrade -install ppm/\$(DISTNAME).ppd
EOF
}
