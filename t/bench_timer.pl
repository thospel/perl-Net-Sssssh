#!/usr/bin/perl -w

# Experiment by developer, not part of the distrivution

use strict;
use warnings;

use Devel::Peek;
use Data::Dumper;
$Data::Dumper::Indent   = 1;
$Data::Dumper::Sortkeys = 1;

my $class = shift || "Timer";

my $LOOPS = 1000;
my $SUB_LOOPS = 5;
my $BETWEEN_LOOPS = 2;
my $TIME_RANGE = 3000;
my $MIN_ELEMS = 0;
my $MAX_ELEMS = 30;
my $CHANCE    = 2.1;

my $verbose = 0;
my ($now, @expire);

package Timer;
# Implements a HEAP
use Scalar::Util qw(weaken);
use Carp;

# Timer indices
sub TIME	() { 0 };
sub INDEX	() { 1 };
sub CODE	() { 2 };	# Must come after INDEX

{
my (@timers, @immediate);
# Timers are kept in a simple binary heap @timers
sub new {
    my ($class, $time, $fun) = @_;

    $time += $now;
    my $i = @timers;
    while ($i > 1 && $time < $timers[$i >> 1][TIME]) {
        weaken($timers[$i] = $timers[$i >> 1]);
        $i = ($timers[$i][INDEX] = $i) >> 1;
    }
    my $timer = bless [$time, $i, $fun], $class;
    weaken($timers[$i] = $timer);
    return $timer;
}

sub delete : method {
    my ($timer) = @_;

    my $i = $timer->[INDEX];
    if (!$i) {
        croak "Not a timer reference" unless defined($i) && $i == 0;
        # Could be a timer sitting on the expired queue in run_now
        $#$timer = INDEX if @$timer > INDEX;
        return;
    }
    $timer->[INDEX] = 0;
    # Last element or beyond...
    if ($i >= $#timers) {
        croak "Not a timer reference" if $i > $#timers;
        pop(@timers);
        return;
    }
    my $time = $timers[-1][TIME];
    if ($i > 1 && $time < $timers[$i >> 1][TIME]) {
        # percolate to root
        do {
            weaken($timers[$i] = $timers[$i >> 1]);
            $i = ($timers[$i][INDEX] = $i) >> 1;
        } while ($i > 1 && $time < $timers[$i >> 1][TIME]);
    } else {
        # percolate to leafs
        my $n = @timers-2;
        my $l = $i * 2;
        while ($l < $n) {
            if ($timers[$l][TIME] < $time) {
                if ($timers[$l+1][TIME] < $timers[$l][TIME]) {
                    weaken($timers[$i] = $timers[$l+1]);
                    $timers[$i][INDEX] = $i;
                    $i = $l+1;
                } else {
                    weaken($timers[$i] = $timers[$l]);
                    $timers[$i][INDEX] = $i;
                    $i = $l;
                }
            } elsif ($timers[$l+1][TIME] < $time) {
                weaken($timers[$i] = $timers[$l+1]);
                $timers[$i][INDEX] = $i;
                $i = $l+1;
            } else {
                last;
            }
            $l = $i * 2;
        }
        if ($l == $n && $timers[$l][TIME] < $time) {
            weaken($timers[$i] = $timers[$l]);
            $timers[$i][INDEX] = $i;
            $i = $l;
        }
    }
    weaken($timers[$i] = pop @timers);
    $timers[$i][INDEX] = $i;
}

# Destroy is needed for entries on @immediate
sub DESTROY {
    shift->delete;
}

sub timeout {
    return
        @timers <= 1 ? "inf" :
        $timers[1][0]-$now > 0 ? $timers[1][0]-$now :
        0;
}

sub time : method {
    return shift->[TIME];
}

sub run_now {
    @timers > 1 || @immediate || return;
    # @immediate must be persistent so no timers get lost if a callback dies
    goto EXPIRED if @timers <= 1 ||
        $timers[1][TIME] > $now;
    while (@timers > 2) {
        push @immediate, $timers[1];
        $timers[1][INDEX] = 0;

        my $time = $timers[-1][TIME];
        my $n = @timers-2;
        my $i = 1;
        my $l = 2;
        while ($l < $n) {
            if ($timers[$l][TIME] < $time) {
                if ($timers[$l+1][TIME] < $timers[$l][TIME]) {
                    weaken($timers[$i] = $timers[$l+1]);
                    $timers[$i][INDEX] = $i;
                    $i = $l+1;
                } else {
                    weaken($timers[$i] = $timers[$l]);
                    $timers[$i][INDEX] = $i;
                    $i = $l;
                }
            } elsif ($timers[$l+1][0] < $time) {
                weaken($timers[$i] = $timers[$l+1]);
                $timers[$i][INDEX] = $i;
                $i = $l+1;
            } else {
                last;
            }
            $l = $i * 2;
        }
        if ($l == $n && $timers[$l][TIME] < $time) {
            weaken($timers[$i] = $timers[$l]);
            $timers[$i][INDEX] = $i;
            $i = $l;
        }
        weaken($timers[$i] = pop @timers);
        $timers[$i][INDEX] = $i;
        goto EXPIRED if $timers[1][TIME] > $now;
    }
    if (@timers == 2) {
        $timers[1][INDEX] = 0;
        push @immediate, pop @timers;
    }
  EXPIRED:
    my $fun;
    defined $fun->[CODE] && push @expire, $fun->[CODE] while $fun = shift @immediate;
    # $fun->[CODE] && $fun->[CODE]->() while $fun = shift @immediate;
}
}

package Timer2;
# Naive ARRAY
use Scalar::Util qw(weaken);

# Timer indices
sub TIME	() { 0 };
sub CODE	() { 1 };

{
my @timers;
my $PLACEHOLDER = [0];

sub new {
    my ($class, $time, $fun) = @_;

    $time += $now;
    my $timer = bless [$time, $fun], $class;
    push @timers, $timer;
    weaken($timers[-1]);
    return $timer;
}

sub run_now {
    @timers = sort { ($a //= $PLACEHOLDER)->[TIME] <=> ($b //= $PLACEHOLDER)->[TIME] } @timers;
    my @immediate;
    push @immediate, shift @timers while @timers && ($timers[0] //= $PLACEHOLDER)->[TIME] <= $now;
    my $fun;
    defined $fun->[CODE] && push @expire, $fun->[CODE] while $fun = shift @immediate;
    # $fun->[CODE] && $fun->[CODE]->() while $fun = shift @immediate;

}

sub time : method {
    return shift->[TIME];
}

sub timeout {
    @timers = sort { ($a //= $PLACEHOLDER)->[TIME] <=> ($b //= $PLACEHOLDER)->[TIME] } @timers;
    shift @timers while @timers && $timers[0][TIME] <= 0;
    return
        !@timers ? "inf" :
        $timers[0][TIME]-$now > 0 ? $timers[0][TIME]-$now :
        0;
}

sub delete {
    my $timer = shift;
    $#$timer = TIME;
    $timer->[TIME] = 0;
}

sub DESTROY {
    shift->delete;
}

}

package Timer3;
# Naive double indexed ARRAY
use Scalar::Util qw(weaken);

# Timer indices
sub TIME	() { 0 };
sub CODE	() { 1 };

{
my @timers;
my $PLACEHOLDER = [0];

sub new {
    my ($class, $time, $fun) = @_;

    $time += $now;
    my $timer = bless [$time, $fun], $class;
    push @timers, [$time, $timer];
    weaken($timers[-1][1]);
    return $timer;
}

sub run_now {
    @timers = sort { $a->[TIME] <=> $b->[TIME] } @timers;
    my @immediate;
    push @immediate, shift @timers while @timers && $timers[0][TIME] <= $now;
    my $fun;
    defined $fun->[CODE] && defined $fun->[CODE][CODE] && push @expire, $fun->[CODE][CODE] while $fun = shift @immediate;
    # $fun->[CODE] && $fun->[CODE]->() while $fun = shift @immediate;

}

sub time : method {
    return shift->[TIME];
}

sub timeout {
    @timers = sort { $a->[TIME] <=> $b->[TIME] } grep $_->[CODE], @timers;
    return
        !@timers ? "inf" :
        $timers[0][TIME]-$now > 0 ? $timers[0][TIME]-$now :
        0;
}

sub delete {
    my $timer = shift;
    $#$timer = TIME;
}

sub DESTROY {
    shift->delete;
}

}

package Timer4;
# Naive ARRAY with minimum
use Scalar::Util qw(weaken);

# Timer indices
sub TIME	() { 0 };
sub CODE	() { 1 };

{
my ($min, @timers);
my $PLACEHOLDER = [0];
my $INFINITY = [9**9**9];

sub new {
    my ($class, $time, $fun) = @_;

    $time += $now;
    my $timer = bless [$time, $fun], $class;
    push @timers, $timer;
    weaken($timers[-1]);
    weaken($min = $timer) if defined $min && $time < $min->[TIME] || @timers == 1;
    return $timer;
}

sub run_now {
    my @immediate;
    if (0) {
        my $i = -1;
        my $m = $INFINITY;
        for my $timer (@timers) {
            $timer && $timer->[CODE] || next;
            my $t = $timer;
            if ($timer->[TIME] <= $now) {
                push @immediate, $t;
                # weaken($immediate[-1]);
            } else {
                weaken($timers[++$i] = $t);
                $m = $timer if $timer->[TIME] < $m->[TIME];
            }
        }
        $#timers = $i;
        if ($m == $INFINITY) {
            $min = undef;
        } else {
            weaken($min = $m);
        }
    } else {
        @timers = sort { ($a //= $PLACEHOLDER)->[TIME] <=> ($b //= $PLACEHOLDER)->[TIME] } @timers;
        my $i = 0;
        ++$i while $i < @timers && $timers[$i][TIME] <= $now;
        if ($i) {
            # This inherits weakness ?
            @immediate = splice(@timers, 0, $i);
        }
        if (@timers) {
            weaken($min = $timers[0]);
        } else {
            $min = undef;
        }
    }

    my $fun;
    defined $fun->[CODE] && push @expire, $fun->[CODE] while $fun = shift @immediate;
    # $fun->[CODE] && $fun->[CODE]->() while $fun = shift @immediate;

}

sub time : method {
    return shift->[TIME];
}

sub timeout {
    return if !@timers;

    return $min->[TIME]-$now > 0 ? $min->[TIME]-$now : 0 if $min && $min->[TIME];
    @timers = sort { ($a //= $PLACEHOLDER)->[TIME] <=> ($b //= $PLACEHOLDER)->[TIME] } @timers;
    shift @timers while @timers && $timers[0][TIME] <= 0;
    if (!@timers) {
        $min = undef;
        return "inf";
    }
    weaken($min = $timers[0]);
    return $min->[TIME]-$now > 0 ? $min->[TIME]-$now : 0;
}

sub delete {
    my $timer = shift;
    $#$timer = TIME;
}

sub DESTROY {
    shift->delete;
}

}

package main;
$now = 0;
srand(8);

my %entries;
my $nr = "0";

sub add {
    # Need a scoped lexical to put in the closure
    my $i = ++$nr;
    my $time = int rand($TIME_RANGE);
    $entries{$i} = $class->new($time, $i);
    # $entries{$i} = $class->new($time, sub { push @expire, $i });
    print "Add nr $i with timeout $time\n" if $verbose;
}

sub remove {
    # Delete
    my @nr = sort { $a <=> $b} keys %entries;
    my $i = $nr[rand @nr];
    delete $entries{$i};
    print "Remove nr $i\n" if $verbose;
}

for my $i (1..$LOOPS) {
    for my $j (1..$SUB_LOOPS) {
        # print Dumper(\%entries);
        my $add;
        my $nr_entries = keys %entries;
        if ($nr_entries <= $MIN_ELEMS) {
            $add = 1;
        } elsif ($nr_entries >= $MAX_ELEMS) {
            $add = 0;
        } else {
            $add = int rand($CHANCE);
        }
        if ($add) {
            add();
        } else {
            remove();
        }
    }
    $class->run_now();
    print "Expire @expire\n" if $verbose;
    delete @entries{@expire};
    @expire = ();
    # Simulate the callbacks also adding and removing timers
    for my $i (1..$BETWEEN_LOOPS) {
        add();
        remove();
    }
    ++$now;
    if ($verbose) {
        my @times = sort {$a <=> $b} map $_->time, values %entries;
        print "NOW=$now, TIMES=@times\n";
    }
    my $timeout = $class->timeout;
    print "Timeout=$timeout\n" if $verbose;
}

# Need to clean %entries
# Without this the mere existence of the add and remove subs causes
# class Timer to massively fail during global destruction
%entries = ();
