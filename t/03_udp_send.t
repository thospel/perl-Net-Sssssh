#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 03_udp_send.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Carp;
BEGIN { $^W = 1 };

use Test::More tests => 3;

use FindBin qw($Bin);
$Bin =~ s{/t/?\z}{} || die "No /t at end of $Bin";

use IO::Socket::INET qw();

my $socket = IO::Socket::INET->new(
    Proto => "udp",
    LocalHost	=> "127.0.0.1",
    # Trick to force bind
    LocalPort => "00") || die "Could not create listening UDP socket: $@";
my $port = $socket->sockport;
ok($port, "Have port $port");
open(my $fh, "-|", "$Bin/bin/udp_send", "-a", "127.0.0.1", $port, "Test") //
    die "Could not fork: $^E";
my $from = $socket->recv(my $buffer, 2**16) //
    die "Could not receive bytes: $^E";
is($buffer, "Test\n", "Expected data");
$socket->send("Waf", 0, $from) // die "Could not send: $^E";
my $out = do { local $/; <$fh> };
close($fh) || die "Could not close udp_send STDOUT: $^E";
is($out, <<"EOF")
Answer: From 127.0.0.1:$port, To 127.0.0.1 [127.0.0.1]
Received: TTL 64, 3 bytes "Waf"
EOF
    ;
