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
    ICMP_HEADER	=> 8,
    DF		=> 2,
    TTL		=> 64,
    TTL_LOW	=> 2,
    PROTO_UDP	=> getprotobyname("udp") // 17,
    PROTO_ICMP	=> getprotobyname("icmp") // 1,

    # IP_PKTINFO is the linux name, can be different on other systems
    # FreeBSD uses IP_RECVDSTADDR
    IP_PKTINFO	=> FREE_BSD ?  undef : 8,
    IP_RECVDSTADDR => FREE_BSD ? 7 : undef,
    IP_RECVTTL	=> LINUX ? 12 : 65,
    IP_TTL	=> LINUX ?  2 :  4,
    # IPPROTO_IP now exists in Socket, but not in really old versions
    IPPROTO_IP	=> 0,

    ICMP_ECHO_REPLY	=> 0,
    ICMP_ECHO_REQUEST	=> 8,
};

use Exporter::Tidy
    constants => [qw(SHORT_MAX IP_VERSION IHL UDP_HEADER DF TTL PROTO_UDP
                     LINUX FREE_BSD
                     IP_PKTINFO IP_RECVDSTADDR IP_RECVTTL IP_TTL IPPROTO_IP
                     ICMP_ECHO_REPLY ICMP_ECHO_REQUEST)],
    other => [qw(parse_address string_from_value fou_encode_udp fou_encode_icmp
                 fou_decode)];

# IPv6 could use [fe80::240:63ff:fede:3c19]:1234 as notation (like RFC 3986)
my %parse_regex = (
    udp4	=> "(?:([^:]*):|^)([^:]*)",
    tcp4	=> "(?:([^:]*):|^)([^:]*)",
);

sub build_parser {
    my ($mode, $types, $matches) = @_;

    my @regex;
    $types = "UDP4" if !defined $types || $types eq "";
    for my $type (split /\|/, $types) {
        my $regex = $parse_regex{lc $type} || die "Unknown $mode type '$type'";
        $regex =~ s/\((?!\?)/(?:/g;
        push @regex, "($regex)";
        push @$matches, "$mode-\L$type";
    }
    # print STDERR "REGEX: <@regex>\n";
    return join("|", @regex);
}

sub parse_address {
    my ($str, $context, %options) = @_;

    my (@matches, @modes);
    my $regex = "";
    for my $mode (qw(from to)) {
        defined(my $types = delete $options{$mode}) || next;
        my $r = build_parser($mode, $types, \@matches);
        $regex = $regex eq "" ? $r : "(?:$regex:)?$r";
        push @modes, $mode;
    }
    croak("Unknown option " . join(", ", map "'$_'", sort keys %options)) if
        %options;
    my @matched = $str =~ /^$regex\z/ or
        die "Could not parse $context '$str'\n";
    my %matches;
    for my $i (0..$#matched) {
        defined(my $matched = $matched[$i]) || next;
        my ($mode, $type) = $matches[$i] =~ /^([^-]+)-([^-]+)\z/ or
            die "Assertion: Impossible match name $matches[$i]";
        my @parts = $matched =~ $parse_regex{$type};
        if ($type eq "udp4" || $type eq "tcp4") {
            if (!defined $parts[0]) {
                $parts[0] = "127.0.0.1";
            } elsif ($parts[0] eq "") {
                $parts[0] = $mode eq "from" ? "0.0.0.0" : "127.0.0.1";
            } elsif ($parts[0] eq "*") {
                die "Cannot connect to $context '*'\n" if $mode eq "to";
                $parts[0] = "0.0.0.0";
            }
            $parts[0] = inet_aton($parts[0]) ||
                die "Could not resolve $context '$parts[0]'\n";

            if (!defined $parts[1] || $parts[1] eq "") {
                die "Missing $context port\n" if $mode eq "to";
                $parts[1] = 0;
            }
            $parts[1] = $parts[1] =~
                # There is no port 0 in /etc/services so we can use ||
                /^0\z|^[1-9][0-9]*\z/ ? int($parts[1]) :
                $type =~ /^udp/ ? getservbyname($parts[1], "udp") ||
                die("$context: Unknown UDP service '$parts[1]'\n") :
                $type =~ /^tcp/ ? getservbyname($parts[1], "tcp") ||
                die("$context: Unknown TCP service '$parts[1]'\n") :
                die("Assertion: Unknown type '$type'");

            #printf(STDERR "$context: UDP4 address %s:%d\n",
            #       inet_ntoa($parts[0]), $parts[1]);
            $matches{$mode} = pack_sockaddr_in($parts[1], $parts[0]);
        } else {
            die "Assertion: Type '$type' not implemented";
        }
        # $matches{$mode} = [$type => \@parts];
    }
    my @result = @matches{@modes} or
        die "Assertion: No modes";
    return @result if wantarray;
    croak "Cannot return multiple results in a scalar" if @result != 1;
    return $result[0];
}

sub string_from_value {
    no warnings "once";
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

sub fou_encode_udp {
    my ($from, $to, $data, $verbose, $ttl) = @_;

    my ($sprt, $src) = unpack_sockaddr_in($from) or
        die "Assertion: Could not unpack from address";
    my ($dprt, $dst) = unpack_sockaddr_in($to) or
        die "Assertion: Could not unpack to address";

    # Avoid real outgoing packet if we are sending to 0.X.X.X
    $ttl = $dst =~ /^\0/ ? TTL_LOW : TTL if !defined $ttl;

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
                      $flags << 13 | 0,
                      $ttl,
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

sub fou_encode_icmp {
    my ($from, $to, $type, $code, $icmp_header, $data, $verbose, $ttl) = @_;

    my $src = inet_aton($from) ||
        die "Assertion: Could not resolve '$from'";
    my $dst = inet_aton($to) ||
        die "Assertion: Could not resolve '$to'";

    # Avoid real outgoing packet if we are sending to 0.X.X.X
    $ttl = $dst =~ /^\0/ ? TTL_LOW : TTL if !defined $ttl;

    my $ip_len = IHL * 4;
    my $buffer = pack("x${ip_len}CCx2a4a*x", $type, $code, $icmp_header, $data);
    my $new_length = length($buffer)-1;
    substr($buffer, 0, $ip_len, "");
    my $sum = unpack("%32n*", $buffer);
    chop $buffer;
    while ($sum > 0xffff) {
        my $carry = $sum >> 16;
        $sum &= 0xffff;
        $sum += $carry;
    }
    substr($buffer, 2, 2, pack("n", 0xffff - $sum));

    my $packet_id = int rand SHORT_MAX;
    my $flags = DF;
    my $header = pack("CCnnnCCx2a4a4",
                      IP_VERSION << 4 | IHL,
                      0,
                      $new_length,
                      $packet_id,
                      $flags << 13 | 0,
                      $ttl,
                      PROTO_ICMP,
                      $src,
                      $dst,
                  );
    $sum = unpack("%32n*", $header);
    while ($sum > 0xffff) {
        my $carry = $sum >> 16;
        $sum &= 0xffff;
        $sum += $carry;
    }
    substr($header, 10, 2, pack("n", 0xffff - $sum));
    substr($buffer, 0, 0, $header);
    if ($verbose) {
        my $props = fou_decode($buffer, $verbose);
        $props->{data} eq $data ||
            die "Assertion: Decode does not invert encode";
        # print Dumper($props);
    }
    return $buffer;
}

sub fou_decode {
    my ($buffer, $verbose, $relaxed) = @_;

    if (length $buffer < 20) {
        my $error = "Packet too short";
        $relaxed || die $error;
        return { error => $error }
    }

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
    # Sanity check on buffer
    if (length($buffer) != $length) {
        my $error = sprintf("Wrong length: %d bytes packet but IP header says %d", length($buffer), $length);
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

    printf($verbose "HEADER: PROTO=%d, DSCP=%d, ECN=%d, ID=%d, FLAGS=%#X, FRAGMENT=%d, TTL=%d, CHKSUM=%#04x, SUM=%#04X, SRC=%s, DST=%s\n",
           $proto, $dscp, $ecn, $packet_id, $flags, $fragment, $ttl, $chksum,
           $sum, inet_ntoa($src), inet_ntoa($dst)) if $verbose;

    # Only UDP
    if ($proto == PROTO_UDP) {
        # Must have space for UDP header
        if ($length < UDP_HEADER) {
            my $error = "Bad UDP length $length";
            $relaxed || die $error;
            return { error => $error }
        }

        my $pseudo10 = pack("a4a4xC", $src, $dst, $proto);

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
            proto	=> "udp",
            ttl		=> $ttl,
            src		=> $src,
            sprt	=> $sprt,
            dst		=> $dst,
            dprt	=> $dprt,
            data	=> $buffer,
        };
    } elsif ($proto == PROTO_ICMP) {
        # Must have space for ICMP header
        if ($length < ICMP_HEADER) {
            my $error = "Bad ICMP length $length";
            $relaxed || die $error;
            return { error => $error }
        }
        # Pad buffer with \0 so a last single byte still gets processed by "n"
        $sum = unpack("%32n*", $buffer . "\x0");
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
        if ($ecn != 0 || $dscp != 0) {
            my $error = "ICMP with ToS != 0";
            $relaxed || die $error;
            return { error => $error }
        }

        my ($type, $code, $icmp_header) = unpack("WWx2a4", substr($buffer, 0, ICMP_HEADER, ""));
        my $props= {
            proto	=> "icmp",
            ttl		=> $ttl,
            src		=> $src,
            dst		=> $dst,
            type	=> $type,
            code	=> $code,
            header_icmp	=> $icmp_header,
            data	=> $buffer,
        };
        if (($type == ICMP_ECHO_REQUEST || $type == ICMP_ECHO_REPLY) && $code == 0) {
            @$props{qw(id seqno)} = unpack("nn", $icmp_header);
        }
        return $props;
    } else {
        my $error = "Wrong proto $proto";
        $relaxed || die $error;
        return { error => $error }
    }
}

1;
