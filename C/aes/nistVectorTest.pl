#!/usr/bin/env perl

# NIST test vectors
# http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
#
# NOTE: These files have DOS line endings which I converted with "dos2unix"

use strict;
use FileHandle;

my $AES_PROG      = './aes';

die "executable \"$AES_PROG\" not found\n"       unless (-x $AES_PROG);

for my $testFile (@ARGV) {
    my ($mode, $keylen) = $testFile =~ /(ECB|CBC|OFB).*(128|192|256)\.rsp/;
    $mode = lc($mode);
    $mode = 'cbc' if $mode eq 'ofb';

    my $cryptMode = undef;

    my $fh = new FileHandle($testFile) or die "can't read file \"$testFile\"\n";
    while (my $line = $fh->getline()) {
        chomp $line;

        if ($line eq '[ENCRYPT]') {
            $cryptMode = "encrypt";
        } elsif ($line eq '[DECRYPT]') {
            $cryptMode = "decrypt";
        }

        next unless $line =~ /^COUNT\s+=\s+(\d+)/;
        my $count = $1;

        die "Undefined cryptMode [encrypt/decrypt]\n" unless defined($cryptMode);

        my ($iv, $key, $plaintext, $ciphertext, $cmd);

        ($key) = $fh->getline() =~ /^KEY\s+=\s+(.*)/;

        if ($mode eq 'cbc') {
            ($iv) = $fh->getline() =~ /^IV\s+=\s+(.*)/;
        }

        if ($cryptMode eq "encrypt") {
            ($plaintext)  = $fh->getline() =~ /^PLAINTEXT\s+=\s+(.*)/;
            ($ciphertext) = $fh->getline() =~ /^CIPHERTEXT\s+=\s+(.*)/;
            $cmd = "/bin/echo -n $plaintext | $AES_PROG -$keylen -encrypt -$mode --hexkey=$key -nopkcs -hex -ohex";
        } else {
            ($ciphertext) = $fh->getline() =~ /^CIPHERTEXT\s+=\s+(.*)/;
            ($plaintext)  = $fh->getline() =~ /^PLAINTEXT\s+=\s+(.*)/;
            $cmd = "/bin/echo -n $ciphertext | $AES_PROG -$keylen -decrypt -$mode --hexkey=$key -nopkcs -hex -ohex";
        }

        $cmd .= " --hexiv=$iv" if ($mode eq 'cbc');

        my $fhProg = new FileHandle("$cmd |") or die "$!";
        my $output = $fhProg->getline();
        $fhProg->close();

        if ($cryptMode eq "encrypt") {
            print "$testFile count: $count mode:$mode($keylen) key:$key\n\tENCRYPT plaintext:$plaintext ciphertext:$ciphertext";
            if ($output ne $ciphertext) {
                print "\n\t$testFile\n";
                print "\n\t$cmd\n";
                print "\n\t$cryptMode FAIL [$output] ne [$ciphertext]\n";
                exit 1;
            }
            printf("\t%s\n", ($output eq $ciphertext) ? "PASS" : "FAIL");
        } else {
            print "$testFile count: $count mode:$mode($keylen) key:$key\n\tDECRYPT ciphertext:$ciphertext plaintext:$plaintext";
            if ($output ne $plaintext) {
                print "\n\t$testFile\n";
                print "\n\t$cmd\n";
                print "\n\t$cryptMode FAIL [$output] ne [$plaintext]\n";
                exit 1;
            }
            printf("\t%s\n", ($output eq $plaintext) ? "PASS" : "FAIL");
        }
    }
    $fh->close();
}
