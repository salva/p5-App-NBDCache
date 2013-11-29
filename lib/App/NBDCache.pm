package App::NBDCache;

our $VERSION = '0.01';

use 5.014;

use strict;
use warnings;

use AnyEvent;
use AnyEvent::Socket;
use Errno ();
use Carp qw(croak cluck verbose);

require Method::WeakCallback;
*_cb = \&Method::WeakCallback::weak_method_callback;

BEGIN { $Class::StateMachine::debug = -1 };

use parent 'Class::StateMachine';
use Class::StateMachine::Declarative
    __any__ => { advance => '_on_done' },
    connecting  => {},
    handshaking => { enter => '_handshake' },
    running => {};

sub proxy {
    my ($class, $sock, $host, $port) = @_;
    my $self = { host => $host,
                 port => $port,
                 fh_client => $sock,
                 in_client  => '',
                 out_client => '',
                 fh_server => undef,
                 in_server  => '',
                 out_server => '' };
    Class::StateMachine::bless $self, $class, 'connecting';

    $self->_connect_to_server;

    $self
}

sub run {
    my $self = shift;
    $self->{cv} = AE::cv;
    $self->{cv}->recv;
}

sub _connect_to_server {
    my $self = shift;
    $self->{in_watcher_server} = tcp_connect $self->{host}, $self->{port}, _cb($self, '_on_connect');
}

sub _on_connect {
    my ($self, $fh) = @_;
    $fh or return $self->_on_error("connection to server failed: $!");

    $self->{fh_server} = $fh;
    $self->_on_done
}

sub _handshake {
    my $self = shift;
    $self->_handshake_1
}

sub _read {
    my ($self, $side, $len, $cb, @cb_args) = @_;
    warn "waiting for $len bytes from $side";
    my $fh = $self->{"fh_$side"};
    if (length $self->{"in_$side"} < $len) {
        $self->{"in_watcher_$side"} = AE::io $fh, 0, _cb($self, '_on_read', $side, $len, $cb, @cb_args);
    }
    else {
        $self->$cb(@cb_args);
    }
}

sub _on_read {
    my ($self, $side, $len, $cb, @cb_args) = @_;
    my $fh = $self->{"fh_$side"};
    my $buf = \$self->{"in_$side"};
    my $missing = $len - length $$buf;
    warn "sysread(". join(", ", $fh, $$buf, $missing, length $$buf) . ")";
    my $bytes = sysread($fh, $$buf, $missing, length $$buf);
    warn "sysread => $bytes";
    if ($bytes) {
        if (length($$buf) >= $len) {
            delete $self->{"in_watcher_$side"};
            $self->$cb(@cb_args);
        }
    }
    elsif (defined $bytes or
           ( ($! != Errno::EAGAIN()) and
             ($! != Errno::EINTR()) ) ) {
        $self->_on_error("read from $side failed: $!");
    }
    # otherwise, just wait for more data
}

sub _read_check_and_forward {
    my ($self, $side, $data, $cb, @cb_args) = @_;
    $self->_read($side, length($data), '_on_check_and_forward', $side, $data, $cb, @cb_args);
}

sub _on_check_and_forward {
    my ($self, $side, $data, $cb, @cb_args) = @_;
    warn qq(comparing >>$self->{"in_$side"}<< against >>$data<<);
    if (substr($self->{"in_$side"}, 0, length $data) eq $data) {
        $self->_forward($side, length $data);
        $self->$cb(@cb_args);
    }
    else {
        $self->_on_error("read $side check failed");
    }
}

sub _read_and_forward {
    my ($self, $side, $len, $cb, @cb_args) = @_;
    $self->_read($side, $len, '_on_read_and_forward', $side, $len, $cb, @cb_args);
}

sub _on_read_and_forward {
    my ($self, $side, $len, $cb, @cb_args) = @_;
    $self->_forward($side, $len);
    $self->$cb(@cb_args);
}

my %other_side = ( server => 'client',
                   client => 'server' );

sub _forward {
    my ($self, $side, $len) = @_;
    my $other_side = $other_side{$side};
    $self->{"out_$other_side"} .= substr($self->{"in_$side"}, 0, $len, '');
    if ($len) {
        $self->{"out_watcher_$other_side"} ||=
            AE::io $self->{"fh_$other_side"}, 1, _cb($self, '_write_data', $other_side);
    }
}

sub _write_data {
    my ($self, $side) = @_;
    my $fh = $self->{"fh_$side"};
    my $buf = $self->{"out_$side"};
    my $bytes = syswrite($fh, $$buf);
    if ($bytes) {
        substr $$buf, 0, $bytes, '';
        unless (length $$buf) {
            delete $self->{"out_watcher_$side"};
        }
    }
    elsif (defined $bytes or
           ( ( $! != Errno::EAGAIN()) and
             ( $! != Errno::EINTR() ) )) {
        $self->_on_error("write $side failed: $!");
    }
}

sub _forward_opts {
    shift->_on_error("forward_opts");
}

sub _handshake_1 { shift->_read_check_and_forward(server => "NBDMAGIC", '_handshake_2') }
sub _handshake_2 { shift->_read_check_and_forward(server => "\x49\x48\x41\x56\x45\x4F\x50\x54", '_handshake_3') }
sub _handshake_3 { shift->_read_and_forward(server => 2, '_handshake_4') }
sub _handshake_4 { shift->_read_and_forward(client => 4, '_handshake_5') }
sub _handshake_5 { shift->_forward_opts }

sub _on_error {
    my ($self, @error) = @_;
    @error = 'unknown' unless @error;
    cluck("something went wrong: @error");
    $self->{cv}->send;
}


1;
__END__


=head1 NAME

App::NBDCache - Perl extension for blah blah blah

=head1 SYNOPSIS

  use App::NBDCache;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for App::NBDCache, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Salvador Fandiño, E<lt>salva@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Salvador Fandiño

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
