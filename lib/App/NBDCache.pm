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

our $debug //= 0;
$debug = ~16384;

use AnyEvent::Debug;
$AnyEvent::Debug::TRACE = 1;
AnyEvent::Debug::wrap(1);

use constant NBD_CMD_READ  => 0;
use constant NBD_CMD_WRITE => 1;
use constant NBD_CMD_DISC  => 2;
use constant NBD_CMD_FLUSH => 3;
use constant NBD_CMD_TRIM  => 4;

use constant NBD_FLAG_HAS_FLAGS  => (1 << 0);
use constant NBD_FLAG_READ_ONLY  => (1 << 1);
use constant NBD_FLAG_SEND_FLUSH => (1 << 2);
use constant NBD_FLAG_SEND_FUA   => (1 << 3);
use constant NBD_FLAG_ROTATIONAL => (1 << 4);
use constant NBD_FLAG_SEND_TRIM  => (1 << 5);

use constant NBD_REQUEST_MAGIC => 0x25609513;
use constant NBD_REPLY_MAGIC   => 0x67446698;

use constant NBD_REQUEST_LENGTH  => 4 + 2 + 2 + 8 + 8 + 4;
use constant NBD_REPLY_LENGTH    => 4 + 4 + 8;

use constant PAGE_BITS => 9;
use constant PAGE_LENGTH => (1 << 9);

use parent 'Class::StateMachine';
use Class::StateMachine::Declarative
    __any__ => { advance => '_on_done' },
    connecting  => {},
    handshaking => { enter => '_handshake' },
    running => {};

sub proxy {
    my ($class, $fh_in, $fh_out, $host, $port) = @_;
    my $self = { host => $host,
                 port => $port,
                 fh_in_client => $fh_in,
                 fh_out_client => $fh_out,
                 in_client  => '',
                 out_client => '',
                 fh_in_server => undef,
                 fh_out_server => undef,
                 in_server  => '',
                 out_server => '',
                 request => {} };
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

    $self->{fh_in_server} = $fh;
    $self->{fh_out_server} = $fh;
    $self->_on_done
}

sub _handshake {
    my $self = shift;
    $self->_handshake_1
}

sub _read {
    my ($self, $side, $len, $cb, @cb_args) = @_;
    _debug(2, "waiting for ", $len, " bytes of data, ", length($self->{"in_$side"}), " already available");
    my $fh = $self->{"fh_in_$side"};
    if (length $self->{"in_$side"} < $len) {
        $self->{"in_length_$side"} = $len;
        _debug(4, "on_read callback: ", $cb, @cb_args);
        $self->{"in_watcher_$side"} = AE::io $fh, 0, _cb($self, '_on_read', $side, $cb, @cb_args);
    }
    else {
        $self->$cb(@cb_args);
    }
}

sub _on_read {
    my ($self, $side, $cb, @cb_args) = @_;

    _debug(4, "on_read callback: ", $cb, @cb_args);

    my $fh = $self->{"fh_in_$side"};
    my $len = $self->{"in_length_$side"};
    my $buf = \$self->{"in_$side"};
    my $missing = $len - length $$buf;
    my $bytes = sysread($fh, $$buf, $missing, length $$buf);
    _debug(2, "sysread($side, $len) => ", $bytes, (defined($bytes) ? '' : ", error: $!"));
    if ($bytes) {
        _hexdump(2, $$buf);
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
    if (substr($self->{"in_$side"}, 0, length $data) eq $data) {
        $self->_forward($side, length $data);
        $self->$cb(@cb_args);
    }
    else {
        _debug(2, "check failed");
        _hexdump(2, substr($self->{"in_$side"}, 0, length $data));
        _debug(2, "against...");
        _hexdump(2, $data);
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
    my $buf = \$self->{"in_$side"};
    $len //= length $$buf;
    if ($len) {
        _debug(2, "forwarding $len bytes from $side to $other_side");
        $self->_write($other_side, substr($$buf, 0, $len, ''));
    }
}

sub _write {
    my $self = shift;
    my $side = shift;
    my $len = length($_[0]);
    if ($len) {
        _debug(2, "writting $len bytes of data to $side");
        _hexdump(2, $_[0]);
        $self->{"out_$side"} .= $_[0];
        $self->{"out_watcher_$side"} //=
            AE::io $self->{"fh_out_$side"}, 1, _cb($self, '_write_data', $side);
    }
}

sub _write_data {
    my ($self, $side) = @_;
    my $fh = $self->{"fh_out_$side"};
    my $buf = \$self->{"out_$side"};
    my $bytes = syswrite($fh, $$buf);
    _debug(2, "syswrite($side, ", length($$buf), ",) => ", $bytes,
           (defined($bytes) ? '' : ", error: $!"));
    if ($bytes) {
        substr $$buf, 0, $bytes, '';
        unless (length $$buf) {
            _debug(2, "$side out buffer is empty");
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
sub _handshake_2 { shift->_read(server => 8, '_handshake_3') }

sub _handshake_3 {
    my $self = shift;
    my $buf = \$self->{in_server};
    if ($$buf eq "\x00\x00\x42\x02\x81\x86\x12\x53") {
        $self->_forward('server');
        $self->_handshake_old_3
    }
    elsif ($$buf eq "\x49\x48\x41\x56\x45\x4F\x50\x54") {
        $self->_forward('server');
        $self->_handshake_new_3
    }
    else {
        _debug(4, "unexpected data read");
        _hexdump(4, $$buf);
        $self->_on_error("unexpected data read");
    }
}

sub _handshake_new_3 {
    shift->_on_error("new handshake not implemented yet");
}

sub _handshake_old_3 {
    shift->_read(server => 8 + 4 + 124, '_handshake_old_4');
}

sub _handshake_old_4 {
    my $self = shift;
    my $buf = \$self->{in_server};
    my ($size, $flags) = unpack 'Q>N', $$buf;
    $self->{size} = $size;
    $self->{flags} = $flags;
    _debug(1, "exported device size: ", $size, sprintf(", 0x%x", $flags));
    $self->_forward('server');

    $self->_do_it
}

sub _do_it {
    my $self = shift;
    $self->_process_client_stream;
    $self->_process_server_stream;
}

sub _process_client_stream {
    my $self = shift;
    $self->_process_client_request('_process_client_stream')
}

sub _process_client_request {
    my $self = shift;
    $self->_read_client_request('_do_client_request', @_);
}

sub _read_client_request {
    my $self = shift;
    $self->_read(client => NBD_REQUEST_LENGTH, @_);
}

my @cmds = qw(READ WRITE DISC FLUSH TRIM);
my @client_request_methods = map "_do_client_request_$_", @cmds;
my @server_reply_methods = map "_do_server_reply_$_", @cmds;

sub _do_client_request {
    my $self = shift;
    my $buf = \$self->{in_client};
    my ($magic, $flags, $cmd, $handle, $offset, $length) = unpack 'Nnna8Q>N', $$buf;
    unless ($magic == NBD_REQUEST_MAGIC) {
        _debugf(1, "bad request magic, expected 0x%x, found 0x%x", NBD_REQUEST_MAGIC, $magic);
        _hexdump(1, $$buf);
        return $self->_on_error("bad request magic");
    }
    _debugf(1, "request received from client: cmd: 0x%x, flags: 0x%x, handle: 0x%x, offset: %d, length: %d",
            $cmd, $flags, unpack('Q>', $handle), $offset, $length);

    my $method = $client_request_methods[$cmd];
    unless (defined $method) {
        _debugf(1, "unsupported command 0x%x", $cmd);
        return $self->_on_error("unsupported command");
    }

    my $request = { flags => $flags,
                    cmd => $cmd,
                    handle => $handle,
                    offset => $offset,
                    length => $length };

    $self->{request}{$handle} = $request;

    $self->$method($request, @_);
}

sub _do_client_request_READ {
    my ($self, $request, $cb, @cb_args) = @_;
    my $offset = $request->{offset};
    my $length = $request->{length};
    my $page0 = $offset >> PAGE_BITS;
    my $page1 = ($offset + $length - 1) >> PAGE_BITS;
    if ($page0 == $page1 ) {
        my $hex = sprintf("%04x", $page0);
        my $fn = join('/', substr($hex, -2, 2), substr($hex, -4, 4), $hex);
        if (open my $fh, '<', $fn) {
            if (seek($fh, $offset - ($page0 << PAGE_BITS), 0)) {
                my $handle = $request->{handle};
                my $buf = pack NNa8 => NBD_REPLY_MAGIC, 0, $handle;
                if (sysread($fh, $buf, $length, NBD_REPLY_LENGTH) == $length) {
                    substr($self->{in_client}, 0, NBD_REQUEST_LENGTH, '');
                    delete $self->{request}{$handle};
                    $self->_write(client => $buf);
                    return $self->$cb(@cb_args);
                }
            }
        }
    }
    $self->_forward('client');
    $self->$cb(@cb_args);
}

sub _do_client_request_WRITE {
    my ($self, $request, @cb) = @_;
    my $offset = $request->{offset};
    my $length = $request->{length};
    my $page0 = $offset >> PAGE_BITS;
    my $page1 = ($offset + $length - 1) >> PAGE_BITS;
    for my $page ($page0..$page1) {
        my $hex = sprintf("%04x", $page);
        my $fn = join('/', substr($hex, -2, 2), substr($hex, -4, 4), $hex);
        unlink $fn;
    }
    $self->_read_and_forward(client => NBD_REQUEST_LENGTH + $request->{length}, @cb);
}

sub _do_client_request_DISC {
    my ($self, $request, @cb) = @_;
    $self->_read_and_forward(client => NBD_REQUEST_LENGTH, @cb);
}

sub _do_client_request_FLUSH {
    my ($self, $request, @cb) = @_;
    $self->_read_and_forward(client => NBD_REQUEST_LENGTH, @cb);
}

sub _do_client_request_TRIM {
    my ($self, $request, @cb) = @_;
    $self->_read_and_forward(client => NBD_REQUEST_LENGTH, @cb);
}

sub _process_server_stream {
    my $self = shift;
    $self->_process_server_reply('_process_server_stream');
}

sub _process_server_reply {
    my $self = shift;
    $self->_read(server => NBD_REPLY_LENGTH, '_do_server_reply', @_);
}

sub _do_server_reply {
    my $self = shift;
    my $buf = \$self->{in_server};
    my ($magic, $error, $handle) = unpack('NNa8', $$buf);

    unless ($magic == NBD_REPLY_MAGIC) {
        _debugf(1, "bad reply magic, expected 0x%x, found 0x%x", NBD_REPLY_MAGIC, $magic);
        _hexdump(1, $$buf);
        return $self->_on_error("bad reply magic");
    }

    _debugf(1, "reply received from server: error: 0x%x, handle: 0x%x", $error, unpack('Q>', $handle));

    my $request = delete $self->{request}{$handle};
    unless (defined $request) {
        _debugf(1, "reply for an unknown request received, handle: 0x%x", unpack('Q>', $handle));
        return $self->_on_error("response mismatch");
    }
    my $method = $server_reply_methods[$request->{cmd}];
    $self->$method($request, @_);
}

sub _do_server_reply_READ {
    my ($self, $request, @cb) = @_;
    _debug(1, "E.C. was here!");
    $self->_read(server => NBD_REPLY_LENGTH + $request->{length}, 'foo', '_do_server_reply_READ_1', @cb); #, $request, @cb);
}

sub _do_server_reply_READ_1 {
    my ($self, $request, $cb, @cb_args) = @_;
    _debug(4, "HERE!");
    my $offset = $request->{offset};
    my $length = $request->{length};
    my $top = $offset + $length;
    my $page0 = $offset >> PAGE_BITS;
    my $page1 = ($offset + $length - 1) >> PAGE_BITS;
    for my $page ($page0 .. $page1) {
        if ($offset <= ($page << PAGE_BITS) and
            $top >= (($page + 1) << PAGE_BITS) ) {
            my $hex = sprintf("%04x", $page);
            my $a = substr($hex, -2, 2);
            mkdir $a;
            my $b = "$a/" . substr($hex, -4, 4);
            mkdir $b;
            my $fn = "$b/$hex";
            my $bytes = -1;
            if (open my $fh, '>', $fn) {
                $bytes = syswrite($fh, $self->{in_server}, ($page << PAGE_BITS) - $offset, PAGE_LENGTH);
            }
            $bytes == PAGE_LENGTH or unlink $fn;
        }
    }
    $self->_forward(server => NBD_REPLY_LENGTH + $request->{length});
    _debug(4, "myself: ", join(', ', map { $_ => $self->{$_} // '<undef>' } keys %$self));
    $self->$cb(@cb_args);
}

sub _do_server_reply_WRITE {
    my ($self, $request, $cb, @cb_args) = @_;
    $self->_forward('server');
    $self->$cb(@cb_args);
}

sub _do_server_reply_DISC {
    my ($self, $request, @cb) = @_;
    $self->_read_and_forward(server => NBD_REPLY_LENGTH, @cb);
}

sub _do_server_reply_FLUSH {
    my ($self, $request, @cb) = @_;
    $self->_read_and_forward(server => NBD_REPLY_LENGTH, @cb);
}

sub _do_server_reply_TRIM {
    my ($self, $request, @cb) = @_;
    $self->_read_and_forward(server => NBD_REPLY_LENGTH, @cb);
}

sub _on_error {
    my ($self, @error) = @_;
    @error = 'unknown' unless @error;
    cluck("something went wrong: @error");
    $self->{cv}->send;
}

sub _debug {
    my $level = shift;
    if ($level & $debug) {
        local ($!, $@);
        print STDERR '# ', (map { defined($_) ? $_ : '<undef>' } @_), "\n"
    }
}

sub _debugf {
    my $level = shift;
    if ($level & $debug) {
        local ($!, $@);
        my $fmt = "# " . shift . "\n";
        no warnings;
        printf STDERR $fmt, map { defined($_) ? $_ : '<undef>' } @_;
    }
}


sub _hexdump {
    my $level = shift;
    if ($level & $debug and 16384 & $debug) {
        local ($!, $@);
        no warnings qw(uninitialized);
        my $data = shift;
        while ($data =~ /(.{1,32})/smg) {
            my $line=$1;
            my @c= (( map { sprintf "%02x",$_ } unpack('C*', $line)),
                    (("  ") x 32))[0..31];
            $line=~s/(.)/ my $c=$1; unpack("c",$c)>=32 ? $c : '.' /egms;
            print STDERR "#> ", join(" ", @c, '|', $line), "\n";
        }
    }
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
