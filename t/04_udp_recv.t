#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 04_udp_recv.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Carp;
BEGIN { $^W = 1 };

use Test::More tests => 5;

use FindBin qw($Bin);
$Bin =~ s{/t/?\z}{} || die "No /t at end of $Bin";

use IO::Socket::INET qw();

my $socket = IO::Socket::INET->new(
    Proto => "udp",
    LocalHost	=> "127.0.0.1",
    # Trick to force bind
    LocalPort => "00") || die "Could not create listening UDP socket: $@";
my $port = $socket->sockport;
my $to = $socket->sockname;
ok($port, "Have port $port");
close($socket) || die "Could not close socket: $^E";

open(my $fh, "-|", "$Bin/bin/udp_recv", "-l1", "-v", "-a", "-p", $port) //
    die "Could not fork: $^E";

$socket = IO::Socket::INET->new(
    Proto => "udp",
    LocalHost	=> "127.0.0.1",
    # Trick to force bind
    LocalPort => "00") || die "Could not create sending UDP socket: $@";
my $send_port = $socket->sockport;
ok($send_port, "Socket is bound");

my $line = <$fh>;
is($line, "=========================\n", "Initial line");
$socket->send("Waf\n", 0, $to) // die "Could not send: $^E";
my $from = $socket->recv(my $buffer, 2**16) //
    die "Could not receive bytes: $^E";
like($buffer, qr{^\d+: Waf\n\z}, "Expected data");
$buffer =~ s/\n/\\n/g;

my $out = do { local $/; <$fh> };
close($fh) || die "Could not close udp_send STDOUT: $^E";
is($out, <<"EOF")
Sender 127.0.0.1:$send_port, Receiver 127.0.0.1 [127.0.0.1]
Received: 4 bytes (TTL 64) "Waf\\n"
Sent: 16 bytes (TTL 63) "$buffer"
=========================
EOF
    ;
