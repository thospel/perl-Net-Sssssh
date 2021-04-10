package Net::Sssssh;

use strict;
use warnings;

our $VERSION = "1.000";

use Socket qw(inet_aton inet_ntoa pack_sockaddr_in unpack_sockaddr_in);
use Carp;
use Data::Dumper;

# The setsockopt option values are unfortunately not in the Socket package
# Se we don't have a OS independent way to get them.
# They also sometimes have different semantics per OS
# So we only support the operating systems we actually tested all this on

use constant {
    LINUX =>
    $^O eq "linux"   ? 1 :
    $^O eq "freebsd" ? 0 :
    die("setsock options only tested on Linux and FreeBSD"),
    FREE_BSD => $^O eq "freebsd" ? 1 : 0,
};

use constant {
    SHORT_MAX	=> int(2**16),
    IP_VERSION	=> 4,
    IHL		=> 5,
    UDP_HEADER	=> 8,
    DF		=> 2,
    TTL		=> 64,
    TTL_LOW	=> 2,
    PROTO_UDP	=> getprotobyname("udp") // 17,

    # IP_PKTINFO is the linux name, can be different on other systems
    # FreeBSD uses IP_RECVDSTADDR
    IP_PKTINFO	=> FREE_BSD ?  undef : 8,
    IP_RECVDSTADDR => FREE_BSD ? 7 : undef,
    IP_RECVTTL	=> LINUX ? 12 : 65,
    IP_TTL	=> LINUX ?  2 :  4,
    # IPPROTO_IP now exists in Socket, but not in really old versions
    IPPROTO_IP	=> 0,
};

use Exporter::Tidy
    constants => [qw(SHORT_MAX IP_VERSION IHL UDP_HEADER DF TTL PROTO_UDP
                     LINUX FREE_BSD
                     IP_PKTINFO IP_RECVDSTADDR IP_RECVTTL IP_TTL IPPROTO_IP)],
    other => [qw(parse_udp_address string_from_value fou_encode fou_decode)];

sub parse_udp_address {
    my ($str, $context, $default_host, $default_port, $prefer_host) = @_;

    my ($host, $port) = $prefer_host && $str !~ /^[0-9]+\z/ ?
        $str =~ /^(?:(.*))(:[^:]*)?\z/ :
        $str =~ /^(?:(.*):)?([^:]*)\z/ or
        die "Could not parse $context '$str'\n";
    if (!defined $host) {
        $host = $default_host // "127.0.0.1" || "0.0.0.0";
    } elsif ($host eq "") {
        $host = $default_host // "0.0.0.0" || "127.0.0.1";
    }
    my $addr = inet_aton($host) || die "Could not resolve $context '$host'\n";
    $port = $port eq "" ? $default_port // die "No port in $context '$str'\n" :
        $port =~ /^0\z|^[1-9][0-9]*\z/ ? int($port) :
        getservbyname($port, "udp") // die "Unknown UDP service '$port'\n";
    die "Port '$port' is out of range" if $port >= 2**16;
    return pack_sockaddr_in($port, $addr);
}

sub string_from_value {
    local $Data::Dumper::Indent	  = 0;
    local $Data::Dumper::Sortkeys = 1;
    local $Data::Dumper::Useqq	  = 1;
    local $Data::Dumper::Trailingcomma = 0;
    # local $Data::Dumper::Varname  = "VAR";
    local $Data::Dumper::Terse = 1;
    local $Data::Dumper::Quotekeys = 0;
    local $Data::Dumper::Sparseseen = 1;
    return Dumper(shift);
}

sub fou_encode {
    my ($from, $to, $data, $verbose) = @_;

    my ($sprt, $src) = unpack_sockaddr_in($from) or
        die "Assertion: Could not unpack from address";
    my ($dprt, $dst) = unpack_sockaddr_in($to) or
        die "Assertion: Could not unpack to address";

    my $packet_id = int rand SHORT_MAX;
    my $flags = DF;

    my $length = length $data;
    my $new_length = $length + IHL * 4 + UDP_HEADER;
    die "Packet too long" if $new_length >= SHORT_MAX;

    my $header = pack("CCnnnCCx2a4a4",
                      IP_VERSION << 4 | IHL,
                      0,
                      $new_length,
                      $packet_id,
                      DF << 13 | 0,
                      # Avoid real outgoing packet if we are sending to 0.X.X.X
                      $dst =~ /^\0/ ? TTL_LOW : TTL,
                      PROTO_UDP,
                      $src,
                      $dst,
                  );
    my $sum = unpack("%32n*", $header);
    while ($sum > 0xffff) {
        my $carry = $sum >> 16;
        $sum &= 0xffff;
        $sum += $carry;
    }
    substr($header, 10, 2, pack("n", 0xffff - $sum));

    my $pseudo10 = pack("a4a4xC", $src, $dst, PROTO_UDP);
    my $udp_header = pack("nnn", $sprt, $dprt, $length + UDP_HEADER);
    $data .= "\0";

    $sum = unpack("%32n*", $pseudo10) + unpack("%32n*", $udp_header) + unpack("%32n*", $data) + $length + UDP_HEADER;

    while ($sum > 0xffff) {
        my $carry = $sum >> 16;
        $sum &= 0xffff;
        $sum += $carry;
    }
    chop $data;
    my $buffer = $header . $udp_header . pack("n", 0xffff - $sum || 0xffff) . $data;

    if ($verbose) {
        my $props = fou_decode($buffer, $verbose);
        $props->{data} eq $data ||
            die "Assertion: Decode does not invert encode";
    }
    return $buffer;
}

sub fou_decode {
    my ($buffer, $verbose, $relaxed) = @_;

    return undef if length $buffer < 20;

    my ($ihl, $ecn, $length, $packet_id, $fragment, $ttl, $proto, $chksum, $src, $dst) = unpack("CCnnnCCna4a4", $buffer);
    my $version = $ihl >> 4;
    $ihl &= 0xf;
    my $flags = $fragment >> 13;
    $fragment &= 0x1fff;
    # only TCP4
    if ($version != IP_VERSION) {
        my $error = "Wrong version $version";
        $relaxed || die $error;
        return { error => $error }
    }
    # Only UDP
    if ($proto != PROTO_UDP) {
        my $error = "Wrong proto $proto";
        $relaxed || die $error;
        return { error => $error }
    }
    # Sanity check on buffer
    if (length($buffer) != $length) {
        my $error = "Wrong length " . length($buffer);
        $relaxed || die $error;
        return { error => $error }
    }
    # We don't handle IP options (yet)
    if ($ihl != IHL) {
        my $error = "Wrong ihl $ihl";
        $relaxed || die $error;
        return { error => $error};
    }
    # Too many hops
    if (!$ttl) {
        my $error = "Bad TTL $ttl";
        $relaxed || die $error;
        return { error => $error }
    }
    # Don't handle fragments (fragment offset)
    if ($fragment) {
        my $error = "Unexpected fragment $fragment";
        $relaxed || die $error;
        return { error => $error }
    }
    # Don't handle fragments (MF flag set)
    if ($flags & 0x1) {
        my $error = "Bad flags $flags";
        $relaxed || die $error;
        return { error => $error }
    }

    my $pseudo10 = pack("a4a4xC", $src, $dst, $proto);

    $ihl *= 4;
    my $header = substr($buffer, 0, $ihl, "");
    $length -= $ihl;

    # No buffer padding needed since length($header) is even
    my $sum = unpack("%32n*", $header);
    while ($sum > 0xffff) {
        my $carry = $sum >> 16;
        $sum &= 0xffff;
        $sum += $carry;
    }
    $sum == 0xffff || die "Bad IP checksum $sum";

    my $dscp = $ecn >> 3;
    $ecn &= 0x7;
    printf($verbose "HEADER: DSCP=%d, ECN=%d, ID=%d, FLAGS=%#X, FRAGMENT=%d, TTL=%d, CHKSUM=%#04x, SUM=%#04X, SRC=%s, DST=%s\n",
           $dscp, $ecn, $packet_id, $flags, $fragment, $ttl, $chksum, $sum,
           inet_ntoa($src), inet_ntoa($dst)) if $verbose;

    # Must have space for UDP header
    if ($length < UDP_HEADER) {
        my $error = "Bad UDP length $length";
        $relaxed || die $error;
        return { error => $error }
    }

    # Pad buffer with \0 so a last single byte still gets processed by "n"
    $sum = unpack("%32n*", $buffer . "\x0") + unpack("%32n*", $pseudo10) + $length;
    my ($sprt, $dprt, $udp_len, $udp_chksum) = unpack("nnnn", substr($buffer, 0, UDP_HEADER, ""));
    if ($udp_len != $length) {
        my $error = "Inconsistent UDP length";
        $relaxed || die $error;
        return { error => $error }
    }
    $length -= UDP_HEADER;

    if ($udp_chksum) {
        while ($sum > 0xffff) {
            my $carry = $sum >> 16;
            $sum &= 0xffff;
            $sum += $carry;
        }
        if ($sum != 0xffff) {
            my $error = "Bad UDP chksum $sum";
            $relaxed || die $error;
            return { error => $error }
        }
    }

    printf($verbose "SPRT=%d, DPRT=%d, LEN=%d, CHK=%04X\n" .
           "Encapsulated FOU packet from %s:%d to %s:%d\n",
           $sprt, $dprt, $udp_len, $udp_chksum,
           inet_ntoa($src), $sprt, inet_ntoa($dst), $dprt) if $verbose;
    return {
        ttl	=> $ttl,
        src	=> $src,
        sprt	=> $sprt,
        dst	=> $dst,
        dprt	=> $dprt,
        data	=> $buffer,
    };
}

1;
