#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 00_load.t'
#########################
# $Id: 00_load.t 4842 2011-11-28 17:31:33Z hospelt $
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

BEGIN { $^W = 1 };
use Test::More tests => 9;

for my $module (qw(Net::Sssssh Net::Sssssh::Package)) {
    use_ok($module) || BAIL_OUT("Cannot even use $module");
}
like(Net::Sssssh::Package->release_time,
     qr{^[0-9]+\z}, "release_time is a number") for 1..2;
is(Net::Sssssh::Package::released("Net::Sssssh", "1.000"),
   "1.000", "Module released");
eval { Net::Sssssh::Package::released("Mumble", "1.000") };
like($@, qr{^Could not find a history for package 'Mumble' at },
     "Expected module not found");
eval { Net::Sssssh::Package::released("Net::Sssssh", "9999") };
like($@,
     qr{^No known version '9999' of package 'Net::Sssssh' at },
     "Expected version not found");
# The fact that this makes cond coverage 100% must be a Devel::Cover bug
eval { Net::Sssssh::Package::released("OogieBoogie", "1.000") };
like($@,
     qr{^Could not find a history for package 'OogieBoogie' at },
     "No history for unknown modules");

ok($^W, "Warnings are still on");
