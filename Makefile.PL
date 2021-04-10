#!/usr/bin/perl -w
# $Id: Makefile.PL 4944 2012-01-04 12:30:35Z hospelt $
use 5.008000;
use strict;
use warnings;
use ExtUtils::MakeMaker;

our $VERSION = '1.000';

WriteMakefile
    (NAME		=> 'Net::Sssssh',
     # finds $VERSION, requires EU::MM from perl >= 5.5
     VERSION_FROM	=> 'lib/Net/Sssssh/Package.pm',
     eval {
         ## no critic (UselessNoCritic MagicNumbers)
         ExtUtils::MakeMaker->VERSION(6.55_01);
         1;
     } ? (BUILD_REQUIRES	=> {
         # Only for the tests
         "Test::More"	=> "0.01",
     }) : (),
     PREREQ_PM		=> {
         "Exporter::Tidy"	=> "0.06",
         "Socket::MsgHdr"	=> "0.04",
     },
     ABSTRACT		=> 'Simple Socket Server over SSH',
     AUTHOR		=> 'Ton Hospel <Net-Sssssh@ton.iguana.be>',
     $^O eq "MSWin32" ? (
         PM_FILTER	=> '$(PERL) -p -e1',
     ) : (),
     clean		=> {
         FILES => '$(DISTNAME).ppd ppm cover_db nytprof nytprof.out* md5-versions.old',
     },
     #LICENSE		=> 'perl',
     #Value must be from legacy list of licenses here
     #http://search.cpan.org/perldoc?Module%3A%3ABuild%3A%3AAPI
 );
