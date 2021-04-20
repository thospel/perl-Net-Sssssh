#!/usr/bin/perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 02_fou_encode_decode.t'
#########################
## no critic (UselessNoCritic MagicNumbers)
use strict;
use warnings;

our $VERSION = "1.000";

use Carp;
BEGIN { $^W = 1 };

use Test::More tests => 6;

use Socket qw(inet_aton pack_sockaddr_in);
use Data::Dumper;
$Data::Dumper::Indent	= 1;
$Data::Dumper::Sortkeys	= 1;

use Net::Sssssh qw(fou_encode_udp fou_decode);

my $from = pack_sockaddr_in(25, inet_aton("1.2.3.4"));
my $to = pack_sockaddr_in(81, inet_aton("6.7.8.9"));
my $data = "Test\nGh\0v";
my $packet = fou_encode_udp($from, $to, $data);
my $props = fou_decode($packet);
is_deeply($props, {
    proto	=> "udp",
    'data' => $data,
    'dprt' => 81,
    'dst' => inet_aton("6.7.8.9"),
    'sprt' => 25,
    'src' => inet_aton("1.2.3.4"),
    'ttl' => 64
}, "Can encode/decode basic packet") ||
    diag(Dumper($props));

$packet = fou_encode_udp($from, $to, $data, undef, 85);
$props = fou_decode($packet);
is_deeply($props, {
    proto	=> "udp",
    'data' => $data,
    'dprt' => 81,
    'dst' => inet_aton("6.7.8.9"),
    'sprt' => 25,
    'src' => inet_aton("1.2.3.4"),
    'ttl' => 85
}, "Can set TTL") ||
    diag(Dumper($props));

$packet = fou_encode_udp($from, $to, $data, undef, 1);
$props = fou_decode($packet);
is_deeply($props, {
    proto	=> "udp",
    'data' => $data,
    'dprt' => 81,
    'dst' => inet_aton("6.7.8.9"),
    'sprt' => 25,
    'src' => inet_aton("1.2.3.4"),
    'ttl' => 1
}, "Can even set TTL 1") ||
    diag(Dumper($props));

$to = pack_sockaddr_in(82, inet_aton("0.0.0.8"));
$packet = fou_encode_udp($from, $to, $data);
$props = fou_decode($packet);
is_deeply($props, {
    proto	=> "udp",
    'data' => $data,
    'dprt' => 82,
    'dst' => inet_aton("0.0.0.8"),
    'sprt' => 25,
    'src' => inet_aton("1.2.3.4"),
    'ttl' => 2
}, "Packet to 0.0.0.x gets TTL 2") ||
    diag(Dumper($props));

eval { fou_encode_udp($from, $to, "a" x 65530) };
like($@, qr{^Packet too long at }, "Cannot encode a huge packet");
eval { fou_decode("abc") };
like($@, qr{^Packet too short at }, "Cannot decode a short packet");

# Should test lots more error packets here
