#
# Tests for the retry policy in P3ClientUA: which failures are worth trying
# again, and the request-replay hazard that dictates retry_request's signature.
#
# Offline apart from two loopback connections that are guaranteed to fail; both
# exist to check our pattern matching against the strings LWP actually produces
# rather than against strings we transcribed by hand.
#
# The plan is done_testing() rather than a count. A fixed count is a second
# place to keep in sync, and getting it wrong reports as a failure of the suite
# rather than of the thing under test.
#

use strict;
use warnings;
use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";

use File::Temp;
use HTTP::Date;
use HTTP::Headers;
use HTTP::Request;
use HTTP::Request::Common;
use HTTP::Response;

BEGIN { use_ok('P3ClientUA'); }

#
# Everything below assumes retries are not switched off in the caller's shell.
#
delete $ENV{P3_HTTP_RETRY_DISABLE};
delete $ENV{P3_HTTP_RETRY_MAX_ELAPSED};

#
# The shape LWP uses for anything that failed on our side of the conversation:
# a synthesized 500 whose real content is the status message.
#
sub lwp_internal
{
    my($message) = @_;

    return HTTP::Response->new(500, $message,
			       HTTP::Headers->new('Content-Type' => 'text/plain',
						  'Client-Warning' => 'Internal response'),
			       $message);
}

sub cf_response
{
    my($code, $ctype, $body, @extra) = @_;

    return HTTP::Response->new($code, 'Cloudflare',
			       HTTP::Headers->new('Server' => 'cloudflare',
						  'CF-Ray' => '8f2c1d4e5a6b7890-ORD',
						  'Content-Type' => $ctype,
						  @extra),
			       $body);
}

# ---------------------------------------------------------------------------
# classify_response: transport failures
# ---------------------------------------------------------------------------

#
# The first of these is the production failure this work exists for: a
# GenomeAnnotationGenbank job died writing its output because the TLS handshake
# to www.bv-brc.org aborted. The retry predicate that shipped before this change
# enumerated reasons ("timeout|connection refused") and did not match it.
#
my @never_sent =
    (
     "Can't connect to www.bv-brc.org:443 (SSL connect attempt failed error:0A000126:SSL routines::unexpected eof while reading)",
     "Can't connect to www.bv-brc.org:443 (Connection timed out)",
     "Can't connect to www.bv-brc.org:443 (Connection refused)",
     "Can't connect to www.bv-brc.org:443 (System error)",
     "Can't connect to www.bv-brc.org:443 (Bad hostname)",
     "Can't connect to 127.0.0.1:35603",
     "Can't connect to proxy.example.org:3128 (Connection refused)",
    );

for my $msg (@never_sent)
{
    is(P3ClientUA::classify_response(lwp_internal($msg)), P3ClientUA::NEVER_SENT,
       "NEVER_SENT: " . substr($msg, 0, 60));
}

my @maybe_sent =
    (
     "read timeout",
     "Server closed connection without sending any data back",
     "Connection reset by peer",
     "Broken pipe",
     "write failed: Connection reset by peer",
     "SSL read error error:0A000126:SSL routines::unexpected eof while reading",
    );

for my $msg (@maybe_sent)
{
    is(P3ClientUA::classify_response(lwp_internal($msg)), P3ClientUA::MAYBE_SENT,
       "MAYBE_SENT: " . substr($msg, 0, 60));
}

#
# A certificate that does not verify will not verify a second later, and LWP
# reports it as a parenthetical on the same "Can't connect" prefix that means
# NEVER_SENT for every other reason -- so the order of the two tests inside
# classify_response is load bearing, and this is what pins it.
#
is(P3ClientUA::classify_response(
       lwp_internal("Can't connect to www.bv-brc.org:443 (certificate verify failed)")),
   P3ClientUA::NO_RETRY, "NO_RETRY: certificate verify failed beats the connect prefix");

# ---------------------------------------------------------------------------
# classify_response: real responses from a real server
# ---------------------------------------------------------------------------

{
    #
    # No client-warning header, so this 500 came from the origin: the service
    # ran our request and blew up doing it. Retrying just runs it again.
    #
    my $res = HTTP::Response->new(500, 'Internal Server Error',
				  HTTP::Headers->new('Content-Type' => 'application/json'),
				  '{"error":"boom"}');
    is(P3ClientUA::classify_response($res), P3ClientUA::NO_RETRY,
       "NO_RETRY: a genuine 500 from the origin");
}

is(P3ClientUA::classify_response(HTTP::Response->new(200, 'OK')), P3ClientUA::NO_RETRY,
   "NO_RETRY: success");

for my $code (400, 401, 403, 404, 409, 422, 501)
{
    is(P3ClientUA::classify_response(HTTP::Response->new($code, 'nope')), P3ClientUA::NO_RETRY,
       "NO_RETRY: $code");
}

for my $code (408, 429, 502, 503, 504)
{
    is(P3ClientUA::classify_response(HTTP::Response->new($code, 'later')), P3ClientUA::MAYBE_SENT,
       "MAYBE_SENT: $code");
}

# ---------------------------------------------------------------------------
# Cloudflare
# ---------------------------------------------------------------------------

#
# All three wire forms of a 1010 seen in production. None is retryable; the edge
# is applying a rule and will apply it again.
#
my $cf_html = cf_response(403, 'text/html; charset=UTF-8', <<'END');
<!DOCTYPE html><html><head><title>Access denied</title></head>
<body><h1>Access denied</h1><h2>Error 1010</h2>
<div class="cf-error-details">Cloudflare Ray ID: 8f2c1d4e5a6b7890</div></body></html>
END

my $cf_json = cf_response(403, 'application/json',
			  '{"error_code":1010,"message":"denied","cloudflare_error":true,"retryable":false}');

my $cf_text = cf_response(403, 'text/plain', "error code: 1010");

for my $pair ([html => $cf_html], [json => $cf_json], [text => $cf_text])
{
    my($label, $res) = @$pair;
    ok(P3ClientUA::is_cloudflare_policy_block($res), "1010 ($label) is a policy block");
    is(P3ClientUA::classify_response($res), P3ClientUA::NO_RETRY, "1010 ($label) is NO_RETRY");
}

#
# The 52x family is Cloudflare saying it could not reach us -- the transient
# condition retries exist for. is_cloudflare_block reports true for these, which
# is why it is the wrong thing to bail a retry loop on.
#
for my $code (521, 522, 523)
{
    my $res = cf_response($code, 'text/html', "<html>Error $code</html>");
    is(P3ClientUA::classify_response($res), P3ClientUA::NEVER_SENT, "CF $code is NEVER_SENT");
    ok(!P3ClientUA::is_cloudflare_policy_block($res), "CF $code is not a policy block");
    ok(P3ClientUA::is_cloudflare_block($res), "CF $code still reads as a Cloudflare block (unchanged)");
}

for my $code (520, 524, 525, 526, 527, 530)
{
    is(P3ClientUA::classify_response(cf_response($code, 'text/html', "<html>Error $code</html>")),
       P3ClientUA::MAYBE_SENT, "CF $code is MAYBE_SENT");
}

{
    my $res = cf_response(429, 'text/html', '<html>rate limited</html>',
			  'CF-Mitigated' => 'challenge');
    ok(!P3ClientUA::is_cloudflare_policy_block($res),
       "a 429 is a rate limit, not a ban, even with CF-Mitigated");
    is(P3ClientUA::classify_response($res), P3ClientUA::MAYBE_SENT, "CF 429 is MAYBE_SENT");
}

#
# A CF-Ray on an ordinary 401 from our login service is not evidence of
# anything: Cloudflare stamps one on everything it proxies.
#
{
    my $res = cf_response(401, 'application/json', '{"error":"bad password"}');
    is(P3ClientUA::classify_response($res), P3ClientUA::NO_RETRY,
       "a proxied 401 is still just a 401");
}

# ---------------------------------------------------------------------------
# retry_after_seconds
# ---------------------------------------------------------------------------

{
    my $res = HTTP::Response->new(429, 'slow down', HTTP::Headers->new('Retry-After' => '30'));
    is(P3ClientUA::retry_after_seconds($res), 30, "Retry-After integer form");

    my $date = HTTP::Date::time2str(time() + 45);
    my $dres = HTTP::Response->new(429, 'slow down', HTTP::Headers->new('Retry-After' => $date));
    my $secs = P3ClientUA::retry_after_seconds($dres);
    ok($secs >= 40 && $secs <= 50, "Retry-After HTTP-date form (got $secs)");

    my $past = HTTP::Date::time2str(time() - 600);
    is(P3ClientUA::retry_after_seconds(
	   HTTP::Response->new(429, 'x', HTTP::Headers->new('Retry-After' => $past))),
       0, "a Retry-After already past reads as 0, not negative");

    is(P3ClientUA::retry_after_seconds(HTTP::Response->new(429, 'x')), undef,
       "no Retry-After header");
}

# ---------------------------------------------------------------------------
# backoff_delay
# ---------------------------------------------------------------------------

for my $attempt (0 .. 8)
{
    my $ceiling = 2 ** $attempt;
    $ceiling = 60 if $ceiling > 60;

    my($lo, $hi) = (1e9, 0);
    for (1 .. 200)
    {
	my $d = P3ClientUA::backoff_delay($attempt);
	$lo = $d if $d < $lo;
	$hi = $d if $d > $hi;
    }
    ok($lo >= $ceiling * 0.5 && $hi <= $ceiling * 1.5,
       "backoff attempt $attempt jitters within [0.5, 1.5] x $ceiling");
}

ok(P3ClientUA::backoff_delay(30) <= 90, "backoff is capped");

# ---------------------------------------------------------------------------
# retry_request
# ---------------------------------------------------------------------------

#
# A fake clock, so the loop can be exercised in microseconds. The sleeper is
# what advances it, which also asserts that the loop actually sleeps for the
# delay it computed.
#
sub harness
{
    my(@responses) = @_;

    my $clock = 0;
    my @sent;

    return
	(
	 sends   => \@sent,
	 elapsed => sub { $clock },
	 opts    => [
		     now      => sub { $clock },
		     sleeper  => sub { $clock += $_[0] },
		     on_retry => sub { },
		     send     => sub {
			 push(@sent, $_[1]);
			 return shift(@responses) // HTTP::Response->new(200, 'OK');
		     },
		    ],
	);
}

{
    my %h = harness(lwp_internal("Can't connect to h:443 (Connection refused)"),
		    lwp_internal("Can't connect to h:443 (Connection refused)"));

    my $res = P3ClientUA::retry_request(undef, sub { HTTP::Request->new(GET => 'http://x/') },
					what => 'test', @{$h{opts}});

    ok($res->is_success, "retry_request retries a NEVER_SENT failure through to success");
    is(scalar @{$h{sends}}, 3, "... taking three attempts");
    ok($h{elapsed}->() > 0, "... and actually waiting between them");
}

{
    my %h = harness(HTTP::Response->new(404, 'Not Found'));

    my $res = P3ClientUA::retry_request(undef, sub { HTTP::Request->new(GET => 'http://x/') },
					@{$h{opts}});

    is($res->code, 404, "a 404 is returned, not retried");
    is(scalar @{$h{sends}}, 1, "... after a single attempt");
}

{
    my %h = harness(HTTP::Response->new(504, 'Gateway Timeout'));

    my $res = P3ClientUA::retry_request(undef, sub { HTTP::Request->new(GET => 'http://x/') },
					idempotent_only => 1, @{$h{opts}});

    is($res->code, 504, "idempotent_only stops on MAYBE_SENT");
    is(scalar @{$h{sends}}, 1, "... after a single attempt");
}

{
    my %h = harness(lwp_internal("Can't connect to h:443 (Connection refused)"));

    my $res = P3ClientUA::retry_request(undef, sub { HTTP::Request->new(GET => 'http://x/') },
					idempotent_only => 1, @{$h{opts}});

    ok($res->is_success, "idempotent_only still retries NEVER_SENT");
    is(scalar @{$h{sends}}, 2, "... taking two attempts");
}

{
    local $ENV{P3_HTTP_RETRY_DISABLE} = 1;

    my %h = harness(lwp_internal("read timeout"));

    my $res = P3ClientUA::retry_request(undef, sub { HTTP::Request->new(GET => 'http://x/') },
					@{$h{opts}});

    is($res->code, 500, "P3_HTTP_RETRY_DISABLE returns the first failure");
    is(scalar @{$h{sends}}, 1, "... after a single attempt");
}

{
    #
    # Never recovers. The budget, not an attempt count, is what stops it.
    #
    my $clock = 0;
    my $sends = 0;

    my $res = P3ClientUA::retry_request(
	undef, sub { HTTP::Request->new(GET => 'http://x/') },
	max_elapsed => 10,
	now         => sub { $clock },
	sleeper     => sub { $clock += $_[0] },
	on_retry    => sub { },
	send        => sub { $sends++; return lwp_internal("read timeout") });

    is($res->code, 500, "budget exhaustion returns the last failure");
    ok($sends > 1, "... having retried ($sends attempts)");
    ok($clock <= 10, "... without overrunning the budget (spent ${clock}s of 10s)");
}

{
    my $clock = 0;
    my $delay;
    my $sends_done = 0;

    P3ClientUA::retry_request(
	undef, sub { HTTP::Request->new(GET => 'http://x/') },
	max_elapsed => 600,
	now         => sub { $clock },
	sleeper     => sub { $clock += $_[0] },
	on_retry    => sub { my %i = @_; $delay //= $i{delay} },
	send        => sub {
	    return $sends_done++ ? HTTP::Response->new(200, 'OK')
		: HTTP::Response->new(429, 'slow down', HTTP::Headers->new('Retry-After' => '120'));
	});

    ok($delay && $delay >= 120, "an explicit Retry-After outranks our backoff (waited ${\ ($delay // 0)}s)");
}

{
    my $err = '';
    eval {
	P3ClientUA::retry_request(undef, HTTP::Request->new(GET => 'http://x/'));
	1;
    } or $err = $@;

    like($err, qr/code ref/,
	 "passing a request object instead of a factory is refused, not silently mishandled");
}

# ---------------------------------------------------------------------------
# The reason retry_request takes a factory
# ---------------------------------------------------------------------------

#
# With DYNAMIC_FILE_UPLOAD set the request body is a callback over a queue of
# parts that it shifts off destructively. Sending the same request object twice
# therefore streams the whole file and then nothing at all -- under the original
# Content-Length, so the upload lands as an empty object with no error raised
# anywhere. This is the hazard that rules out an LWP::UserAgent subclass and
# dictates retry_request's signature; if this test ever fails, the factory
# requirement can be relaxed.
#
{
    my $tmp = File::Temp->new(SUFFIX => '.dat');
    print $tmp "x" x 50000;
    close($tmp);
    my $size = -s "$tmp";

    local $HTTP::Request::Common::DYNAMIC_FILE_UPLOAD = 1;

    my $req = HTTP::Request::Common::POST('http://example.org/node',
					  Content_Type => 'form-data',
					  Content => [upload => ["$tmp"]]);

    is(ref($req->content), 'CODE', "DYNAMIC_FILE_UPLOAD makes the body a callback");

    my $drain = sub {
	my $cb = $req->content;
	my $n = 0;
	while (defined(my $chunk = $cb->()))
	{
	    last unless length $chunk;
	    $n += length $chunk;
	}
	return $n;
    };

    my $first = $drain->();
    my $second = $drain->();

    ok($first >= $size, "first send streams the whole file ($first bytes, file is $size)");
    is($second, 0, "second send of the SAME request object streams nothing");
    cmp_ok($req->header('Content-Length') // 0, '>=', $size,
	   "... while Content-Length still promises the full body");
}

# ---------------------------------------------------------------------------
# What LWP actually says, as opposed to what we think it says
# ---------------------------------------------------------------------------

#
# Loopback only: port 1 is never listening, so this is fast and needs no
# network. The point is to check the real message against our matcher rather
# than a string transcribed from memory.
#
{
    my $ua = P3ClientUA::new_ua(timeout => 5);
    my $res = $ua->get('http://127.0.0.1:1/');

    ok(!$res->is_success, "a connection to 127.0.0.1:1 fails");
    is(P3ClientUA::classify_response($res), P3ClientUA::NEVER_SENT,
       "a refused connection classifies NEVER_SENT (LWP said: " . $res->message . ")");
}

#
# Speak https at a plaintext listener and the TLS handshake dies -- the closest
# reproduction of the production failure that needs no certificates, and the
# case the old reason-enumerating predicate missed.
#
SKIP: {
    eval { require IO::Socket::INET; require LWP::Protocol::https; 1 }
	or skip("IO::Socket::INET or LWP::Protocol::https unavailable", 2);

    my $listener = IO::Socket::INET->new(LocalAddr => '127.0.0.1', Listen => 5, Proto => 'tcp')
	or skip("cannot bind a loopback listener", 2);
    my $port = $listener->sockport;

    my $ua = P3ClientUA::new_ua(timeout => 5);
    my $res = $ua->get("https://127.0.0.1:$port/");

    ok(!$res->is_success, "https to a plaintext listener fails");
    is(P3ClientUA::classify_response($res), P3ClientUA::NEVER_SENT,
       "a failed TLS handshake classifies NEVER_SENT (LWP said: " . $res->message . ")");

    close($listener);
}

done_testing();
