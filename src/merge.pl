#!/usr/bin/env perl

use strict;
use warnings;

# Run at the command prompt as perl merge_xml.pl file1.xml file2.xml file3.xml > big.xml
# This suggested code will accommodate as many files as you want to merge. It uses the
# following entries as unique ID
# Code: <tv generator-info-name="xxx" generator-info-url="www.xxx.com">

my $header = qq(<?xml version="1.0" encoding="ISO-8859-1"?>);
my $subheader = qq(<!DOCTYPE tv SYSTEM "xmltv.dtd">);
my @tv_queue;
my %tv = ();

{
    local $/="</tv>\n";
    while(<>) {
        my ($generator) = /(<tv.*>)/;
        if (!$tv{$generator}){
            push @tv_queue, $generator;
        }
        push @{$tv{$generator}[0]}, /(\s{2}<channel.*channel>)/sm;
        push @{$tv{$generator}[1]}, /(\s{2}<programme.*programme>)/sm;
    }
}

print "$header\n";
print "$subheader\n";
print "\n";

for my $g (@tv_queue){
    print "$g\n";
    for my $i (@{$tv{$g}}) {
        print join("\n", @{$i}), "\n";
    }
    print "</tv>\n";
}
