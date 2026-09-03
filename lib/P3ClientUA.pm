package P3ClientUA;

use strict;
use LWP::UserAgent;
use HTTP::Response;
use Exporter 'import';

our @EXPORT_OK = qw(new_ua user_agent_string debug_enabled
		    is_cloudflare_block http_failure_message dump_http_failure
		    is_cloudflare_policy_block classify_response retry_request
		    retry_after_seconds retry_disabled backoff_delay
		    detect_truncated_body
		    NO_RETRY NEVER_SENT MAYBE_SENT);

#
# The BV-BRC sites sit behind Cloudflare, which rejects some default library
# user-agents outright (error 1010). LWP's default is one of them, so every
# client in this tree must present an allowlisted agent string instead.
#
our $default_user_agent = "BV-BRC P3 Client";

#
# Undef leaves LWP's own default in place; callers that want a short leash
# (the login and token-validation paths) pass timeout explicitly. Do not put a
# value here: several callers are bulk data clients that must not be cut off.
#
our $default_timeout = undef;

#
# Number of bytes of a failing response body we are willing to print.
#
our $body_dump_limit = 2048;

#
# Headers whose values may carry credentials. Never printed.
#
my %redact = map { lc($_) => 1 } qw(authorization cookie set-cookie
				    proxy-authorization x-auth-token);

=head1 BV-BRC HTTP Client Utilities

Shared construction and failure diagnosis for the LWP-based clients in this
tree. Two problems this addresses:

=over 4

=item *

The BV-BRC web sites sit behind Cloudflare, which bans the default
C<libwww-perl> user-agent (error 1010). Every user agent must be built with
L</new_ua> so it presents an allowlisted string.

=item *

When a request is rejected, the interesting evidence (status, C<CF-Ray> id,
response headers) was being discarded. L</http_failure_message> folds the
essentials into the die message, and L</dump_http_failure> prints the full
exchange when diagnostics are enabled.

=back

Diagnostics are enabled by setting C<P3_DEBUG_HTTP> in the environment (the
C<--debug-http> flag on L<p3-login> does this for you).

=head2 Utility Routines

=head3 user_agent_string

    $ua_string = P3ClientUA::user_agent_string()

The agent string to present to the BV-BRC services. C<$FIG_Config::p3_data_api_user_agent>
wins if set, then the C<P3_USER_AGENT> environment variable, then a built-in
default.

=cut

sub user_agent_string
{
    #
    # Read FIG_Config defensively; this module is in p3_auth, which does not
    # depend on p3_core, so FIG_Config may never have been loaded.
    #
    no strict 'refs';
    my $configured = ${"FIG_Config::p3_data_api_user_agent"};

    return $configured || $ENV{P3_USER_AGENT} || $default_user_agent;
}

=head3 new_ua

    $ua = P3ClientUA::new_ua(%options)

Create an L<LWP::UserAgent> carrying the allowlisted user agent string. Options
are passed through to the L<LWP::UserAgent> constructor, except C<timeout>,
which is applied after construction; when it is not given, LWP's own default is
left alone.

=cut

sub new_ua
{
    my(%opts) = @_;

    my $timeout = exists $opts{timeout} ? delete $opts{timeout} : $default_timeout;

    my $ua = LWP::UserAgent->new(%opts);
    $ua->agent(user_agent_string());
    $ua->timeout($timeout) if defined $timeout;

    return $ua;
}

=head3 debug_enabled

    $flag = P3ClientUA::debug_enabled()

True when HTTP diagnostics have been requested via the C<P3_DEBUG_HTTP>
environment variable.

=cut

sub debug_enabled
{
    return $ENV{P3_DEBUG_HTTP} ? 1 : 0;
}

=head3 is_cloudflare_block

    $flag = P3ClientUA::is_cloudflare_block($res)

True when the L<HTTP::Response> came from Cloudflare's edge rather than from our
own service.

Note that a C<CF-Ray> header is B<not> evidence of a block: Cloudflare stamps
one on everything it proxies, including a perfectly ordinary 401 from our login
service. What distinguishes a block is C<CF-Mitigated>, the text of a Cloudflare
error page, or one of Cloudflare's own status codes served as HTML.

=cut

#
# Statuses Cloudflare itself generates when it refuses or cannot reach the
# origin. 403 covers the WAF/user-agent blocks (error 1010) we care about most.
#
my %cf_status = map { $_ => 1 } (403, 429, 503, 520 .. 527, 530);

sub is_cloudflare_block
{
    my($res) = @_;

    return 0 unless $res;
    return 0 if $res->is_success;

    return 1 if $res->header('CF-Mitigated');

    #
    # Cloudflare serves its rejection either as an HTML error page or, for a
    # request that asked for JSON, as a JSON document carrying
    # "cloudflare_error":true and "error_code":1010. Match both.
    #
    my $body = eval { $res->decoded_content(charset => 'none') } // $res->content // '';
    return 1 if $body =~ /Error\s+(?:code)?\s*:?\s*10\d\d|Attention Required|Cloudflare Ray ID|cf-error-details|__cf_chl/i;
    return 1 if $body =~ /"cloudflare_error"\s*:\s*true|"error_code"\s*:\s*10\d\d/i;

    #
    # Otherwise: an error page from the edge is HTML, while our services answer
    # in JSON.
    #
    my $server = $res->header('Server') // '';
    my $ctype = $res->header('Content-Type') // '';
    return 1 if $server =~ /cloudflare/i
	&& $cf_status{$res->code}
	&& $ctype =~ m,text/html,i;

    return 0;
}

=head3 cloudflare_ray

    $ray = P3ClientUA::cloudflare_ray($res)

The C<CF-Ray> identifier from the response, or undef. This is the value
Cloudflare support asks for when investigating a block.

=cut

sub cloudflare_ray
{
    my($res) = @_;

    return undef unless $res;
    return $res->header('CF-Ray');
}

=head3 http_failure_message

    $msg = P3ClientUA::http_failure_message($res, $what)

A one-line description of a failed request, suitable for passing to C<die>.
C<$what> names the operation ("Login", "Refresh", ...). When the failure came
from Cloudflare the message says so and includes the C<CF-Ray> id and, if we can
pick it out of the block page, the Cloudflare error number.

=cut

sub http_failure_message
{
    my($res, $what) = @_;

    $what ||= "Request";

    if (!$res)
    {
	return "$what failed (no response)\n";
    }

    my $msg = "$what failed: " . $res->status_line;

    my $body = eval { $res->decoded_content(charset => 'none') } // $res->content // '';

    if (is_cloudflare_block($res))
    {
	$msg .= " - blocked by Cloudflare";

	if ($body =~ /"error_code"\s*:\s*(10\d\d)/i || $body =~ /Error\s+(?:code)?\s*:?\s*(10\d\d)/i)
	{
	    my $code = $1;
	    $msg .= " (error $code" . ($code eq '1010' ? ": user-agent not allowed" : "") . ")";
	}

	$msg .= ". The user agent presented was '" . user_agent_string() . "'.";
    }
    else
    {
	#
	# The body is our service talking. Show the first line of it.
	#
	$body =~ s/\s+$//;
	my($first) = split(/\n/, $body);
	if (defined($first) && $first =~ /\S/ && $first !~ /^\s*</)
	{
	    $msg .= " - " . substr($first, 0, 200);
	}
    }

    #
    # Always report the Ray id when there is one: it identifies this exact
    # request at the edge, which is what Cloudflare support asks for, and it is
    # present whether or not the edge is what rejected us.
    #
    if (my $ray = cloudflare_ray($res))
    {
	$msg .= " [CF-Ray $ray]";
    }

    if (!debug_enabled())
    {
	$msg .= " Re-run with P3_DEBUG_HTTP=1 for the full HTTP headers.";
    }

    return "$msg\n";
}

=head3 dump_http_failure

    P3ClientUA::dump_http_failure($res, $fh)

Print the request and response headers of a failed exchange to C<$fh>
(STDERR by default), so they can be pasted into a support ticket.

Credential-bearing headers are redacted and the request body is never printed:
the login request body is the user's password, and C<login_rast> puts the
password in a Basic C<Authorization> header.

=cut

sub dump_http_failure
{
    my($res, $fh) = @_;

    $fh ||= \*STDERR;

    print $fh "---- BV-BRC HTTP diagnostics ----\n";
    print $fh "Client user agent: " . user_agent_string() . "\n";

    if (!$res)
    {
	print $fh "No response object available.\n";
	print $fh "---- end HTTP diagnostics ----\n";
	return;
    }

    if (my $req = $res->request)
    {
	print $fh "Request: " . $req->method . " " . $req->uri . "\n";
	_print_headers($fh, $req->headers, "  ");
	print $fh "  (request body not shown; it may contain credentials)\n"
	    if defined($req->content) && length($req->content);
    }

    print $fh "Response: " . $res->status_line . "\n";
    _print_headers($fh, $res->headers, "  ");

    my $body = eval { $res->decoded_content(charset => 'none') } // $res->content // '';
    if (length($body))
    {
	my $shown = substr($body, 0, $body_dump_limit);
	print $fh "Response body (" . length($body) . " bytes";
	print $fh ", first $body_dump_limit shown" if length($body) > $body_dump_limit;
	print $fh "):\n$shown\n";
	print $fh "\n" unless $shown =~ /\n$/;
    }
    else
    {
	print $fh "Response body: (empty)\n";
    }

    print $fh "---- end HTTP diagnostics ----\n";
}

sub _print_headers
{
    my($fh, $headers, $indent) = @_;

    for my $name (sort $headers->header_field_names)
    {
	for my $value ($headers->header($name))
	{
	    if ($redact{lc $name})
	    {
		$value = "<redacted, " . length($value) . " bytes>";
	    }
	    print $fh "$indent$name: $value\n";
	}
    }
}


=head2 Retry Policy

A transient network fault -- a dropped TLS handshake, a socket reset, a service
that stalls for ten seconds -- surfaces to an LWP client as a failed request
indistinguishable in shape from a permanent one. The routines below decide
which is which, so a caller can retry the transient ones without hammering the
permanent ones.

The classification is keyed on B<evidence of delivery>, not on which method was
called: a shared HTTP client cannot know whether C<create> is idempotent for
the service on the other end, but it always knows whether the request made it
onto the wire.

=head3 classify_response

    $class = P3ClientUA::classify_response($res)

Classify an L<HTTP::Response> into one of three retry classes:

=over 4

=item C<NEVER_SENT>

The request provably did not reach the service: the connection, DNS lookup or
TLS handshake failed, or Cloudflare could not reach the origin at all. Retrying
is safe for B<any> method, including one that mutates state.

=item C<MAYBE_SENT>

The request went out but the answer did not come back: a read timeout, a
connection dropped mid-exchange, a 502/503/504 from a proxy. The service may
have performed the operation. Retrying risks a duplicate.

=item C<NO_RETRY>

Retrying will not help: success, any 4xx, a genuine 5xx from the origin, a
Cloudflare policy block, a certificate that does not verify.

=back

=cut

use constant {
    NO_RETRY   => 'NO_RETRY',
    NEVER_SENT => 'NEVER_SENT',
    MAYBE_SENT => 'MAYBE_SENT',
};

#
# Cloudflare's origin-side error codes. 521/522/523 all mean the edge could not
# get a connection to us, so nothing we sent was ever delivered; the rest mean
# the exchange started and went wrong somewhere after that.
#
my %cf_never_sent = map { $_ => 1 } (521, 522, 523);
my %cf_maybe_sent = map { $_ => 1 } (520, 524, 525, 526, 527, 530);

sub classify_response
{
    my($res) = @_;

    return NO_RETRY unless $res;
    return NO_RETRY if $res->is_success;

    my $code = $res->code;

    #
    # A policy block is a decision, and the edge will make the same decision
    # again in a millisecond's time. Note this is deliberately narrower than
    # is_cloudflare_block, which also covers the 52x family below.
    #
    return NO_RETRY if is_cloudflare_policy_block($res);

    #
    # LWP does not have a status code for "the network broke", so it synthesizes
    # a 500 and marks it with this header. The header is the discriminator that
    # keeps a genuine 500 from the origin -- which we must not hammer -- out of
    # the retry path entirely.
    #
    if ($code == 500 && ($res->header('client-warning') // '') eq 'Internal response')
    {
	#
	# The reason lands in the status message; some protocol handlers repeat
	# it in the body and put nothing useful in the message, so match both.
	#
	my $body = eval { $res->decoded_content(charset => 'none') } // $res->content // '';
	my $text = ($res->message // '') . "\n" . $body;

	#
	# Must be tested before the connect prefix below: LWP reports a failed
	# peer verification as a parenthetical on the "Can't connect" string, and
	# a certificate that does not verify now will not verify on the retry.
	#
	return NO_RETRY if $text =~ /certificate verify failed/i
	    || $text =~ /certificate has expired/i
	    || $text =~ /hostname verification failed/i
	    || $text =~ /can't verify SSL peers/i;

	#
	# LWP::Protocol::http builds "Can't connect to $host:$port" before it
	# knows why it failed, appending a parenthetical only when it can extract
	# one. Anchoring on the prefix therefore covers every connect-phase
	# failure -- refused, timed out, TLS handshake aborted, DNS -- including
	# reasons LWP has not invented yet. Enumerating the reasons instead is
	# how the previous version of this predicate came to miss the SSL
	# "unexpected eof while reading" that killed a production job.
	#
	return NEVER_SENT if $text =~ /^Can't connect to /m;
	return NEVER_SENT if $text =~ /proxy connect failed/i;
	return NEVER_SENT if $text =~ /Bad hostname/i
	    || $text =~ /could not resolve/i
	    || $text =~ /name or service not known/i
	    || $text =~ /temporary failure in name resolution/i;

	#
	# Anything else internal happened with the request already on the wire:
	# read timeout, connection reset, the server closing a kept-alive socket
	# in the instant between our two requests.
	#
	return MAYBE_SENT;
    }

    if (_looks_like_cloudflare($res))
    {
	return NEVER_SENT if $cf_never_sent{$code};
	return MAYBE_SENT if $cf_maybe_sent{$code};
    }

    #
    # The BV-BRC data API answers a backend outage with its own 500 carrying the
    # real 503 quoted in the message, so the transient failure arrives wearing
    # the status code we most need to keep out of the retry path. Unwrap it.
    #
    return MAYBE_SENT if $code == 500 && _wraps_upstream_5xx($res);

    #
    # 429 reaches here rather than being treated as a Cloudflare mitigation: it
    # is the one edge response that means "not now" rather than "not ever", and
    # it usually carries a Retry-After saying exactly how long.
    #
    return MAYBE_SENT if $code == 408 || $code == 429
	|| $code == 502 || $code == 503 || $code == 504;

    return NO_RETRY;
}

=head3 _wraps_upstream_5xx

True when an origin 5xx is a wrapper around a transient failure further back,
rather than the origin's own defect. The case this exists for is the data API
returning

    {"status":500,"message":"Unable to parse the query response.
     <html><body><h1>503 Service Unavailable</h1>
     No server is available to handle this request.</body></html>"}

when its Solr nodes are down: the API proxies to a load balancer, fails to parse
the balancer's HTML error page as a query result, and reports that parse failure
as a 500 of its own. A query-node restart fixes it in seconds, but classified on
the status code alone it is a genuine origin 500 and never retried -- which is
how a node outage killed both BLAST build drivers outright rather than stalling
them.

Deliberately narrow. It requires an embedded upstream status B<line> -- a 502,
503 or 504 in an HTML heading or status position -- or haproxy's distinctive
"no server is available" text. A 500 whose body merely mentions one of those
numbers does not match, because the cost of a false positive here is hammering
an origin that is already failing.

=cut

sub _wraps_upstream_5xx
{
    my($res) = @_;

    return 0 unless $res;

    my $body = eval { $res->decoded_content(charset => 'none') } // $res->content // '';
    return 0 unless length $body;

    #
    # haproxy's own text, which is what the balancer in front of Solr emits and
    # what the API quotes verbatim. Checked first because it is unambiguous.
    #
    return 1 if $body =~ /No server is available to handle this request/i;

    #
    # An embedded status line: "<h1>503 Service Unavailable</h1>", or the same
    # pair at the head of a quoted plain-text response. Requiring the reason
    # phrase alongside the code is what keeps this from matching a 500 that
    # happens to contain the digits.
    #
    return 1 if $body =~ /\b502\s+Bad\s+Gateway/i;
    return 1 if $body =~ /\b503\s+Service\s+(?:Unavailable|Temporarily)/i;
    return 1 if $body =~ /\b504\s+Gateway\s+Time-?\s?out/i;

    return 0;
}

sub _looks_like_cloudflare
{
    my($res) = @_;

    return 0 unless $res;
    return 1 if ($res->header('Server') // '') =~ /cloudflare/i;
    return 1 if $res->header('CF-Ray');

    return 0;
}

=head3 is_cloudflare_policy_block

    $flag = P3ClientUA::is_cloudflare_policy_block($res)

True when Cloudflare refused the request itself -- the C<10xx> WAF family, of
which C<1010> (banned user agent) is the one this tree keeps meeting. These
carry C<"retryable":false> for a reason: the edge is applying a rule, and it
will apply the same rule to the retry.

This is deliberately narrower than L</is_cloudflare_block>, which also reports
true for the C<520>-C<527> family. Those mean Cloudflare could not reach our
origin, which is exactly the transient condition a retry exists to paper over --
so L</is_cloudflare_block> is the wrong predicate to bail a retry loop on, and
its meaning is pinned by tests and by C<P3DataAPI>. Leave it alone.

=cut

sub is_cloudflare_policy_block
{
    my($res) = @_;

    return 0 unless $res;
    return 0 if $res->is_success;

    #
    # 429 is a rate limit, not a ban. It is the only mitigation for which
    # trying again is the correct response, so it is never a policy block.
    #
    return 0 if $res->code == 429;

    return 1 if $res->header('CF-Mitigated');

    my $body = eval { $res->decoded_content(charset => 'none') } // $res->content // '';
    return 1 if $body =~ /"cloudflare_error"\s*:\s*true|"error_code"\s*:\s*10\d\d/i;
    return 1 if $body =~ /Error\s+(?:code)?\s*:?\s*10\d\d|Attention Required|cf-error-details|__cf_chl/i;

    return 0;
}

=head3 detect_truncated_body

    $res = P3ClientUA::detect_truncated_body($res)
    $res = P3ClientUA::detect_truncated_body($res, $bytes_received)

Returns C<$res> unchanged, unless the body came up short of the
C<Content-Length> the server promised -- in which case it returns a synthesized
502 naming the shortfall, which L</classify_response> treats as C<MAYBE_SENT>
and so retries.

This exists because LWP does not notice. Measured against a server that closes
the connection mid-body: the response is C<200 OK>, carries the full
C<Content-Length>, and has no C<X-Died>, C<Client-Aborted> or C<Client-Warning>
header of any kind. A caller that trusts C<is_success> writes a truncated file
and reports success -- worse than a failed download, because nothing downstream
can tell.

Pass C<$bytes_received> when the body went to a C<:content_cb> and so is not in
C<$res>; it defaults to the length of the response content. A response with no
C<Content-Length> (a chunked transfer) cannot be checked this way and is
returned unchanged.

=cut

sub detect_truncated_body
{
    my($res, $received) = @_;

    return $res unless $res && $res->is_success;

    my $want = $res->content_length;
    return $res unless defined($want);

    $received = length($res->content // '') unless defined($received);
    return $res if $received >= $want;

    my $short = HTTP::Response->new(502, "Truncated response body: received $received of $want bytes",
				    $res->headers->clone);
    $short->request($res->request) if $res->request;

    return $short;
}

=head3 retry_after_seconds

    $secs = P3ClientUA::retry_after_seconds($res)

The C<Retry-After> hint from the response in seconds, handling both the integer
and the HTTP-date spellings, or undef when there is none. A date already in the
past reads as 0 rather than as a negative delay.

=cut

sub retry_after_seconds
{
    my($res) = @_;

    return undef unless $res;

    my $hdr = $res->header('Retry-After');
    return undef unless defined($hdr) && $hdr =~ /\S/;

    $hdr =~ s/^\s+//;
    $hdr =~ s/\s+$//;

    return $hdr + 0 if $hdr =~ /^\d+$/;

    my $when = eval { require HTTP::Date; HTTP::Date::str2time($hdr) };
    return undef unless defined $when;

    my $delta = $when - time();
    return $delta > 0 ? $delta : 0;
}

=head3 retry_disabled

    $flag = P3ClientUA::retry_disabled()

True when C<P3_HTTP_RETRY_DISABLE> is set. This exists for the callers that need
to observe a fault rather than survive it -- the workspace health check must be
able to see the outage it is there to detect, and a test suite must not spend
minutes backing off before reporting a failure it expected.

=cut

sub retry_disabled
{
    return $ENV{P3_HTTP_RETRY_DISABLE} ? 1 : 0;
}

=head3 default_max_elapsed

    $secs = P3ClientUA::default_max_elapsed()

The wall-clock budget a retry loop is allowed to spend, from
C<P3_HTTP_RETRY_MAX_ELAPSED> or C<$P3ClientUA::default_max_elapsed> (300s).

The budget is a duration rather than an attempt count on purpose: what an
operator needs to reason about is "this call must not hang for more than N
minutes", and offering both knobs invites them to disagree.

=cut

our $default_max_elapsed = 300;

sub default_max_elapsed
{
    my $env = $ENV{P3_HTTP_RETRY_MAX_ELAPSED};
    return $env + 0 if defined($env) && $env =~ /^\s*\d+(?:\.\d+)?\s*$/;

    return $default_max_elapsed;
}

=head3 backoff_delay

    $secs = P3ClientUA::backoff_delay($attempt)

Seconds to wait before attempt C<$attempt> (0-based): exponential, capped at
C<$P3ClientUA::backoff_cap>, with full jitter.

The jitter is not decoration. A fixed schedule is aligned to the second, so a
service that stalls and recovers releases every client that was waiting on it
in the same tick -- and a thousand concurrent annotation jobs promptly collide
again.

=cut

our $backoff_base = 1;
our $backoff_cap = 60;

sub backoff_delay
{
    my($attempt) = @_;

    my $ceiling = $backoff_base * (2 ** ($attempt || 0));
    $ceiling = $backoff_cap if $ceiling > $backoff_cap;

    return $ceiling * (0.5 + rand());
}

=head3 retry_request

    $res = P3ClientUA::retry_request($ua, $make_request, %opts)

Issue a request, retrying it while L</classify_response> says the failure was
transient and the elapsed budget has not run out. Returns the last
L<HTTP::Response>, successful or not; it never dies on an HTTP failure, so the
caller's existing error handling is unchanged.

B<C<$make_request> is a closure returning a fresh L<HTTP::Request>, not a
request object.> This is the signature and not a convention because replaying a
request object silently corrupts an upload: with
C<$HTTP::Request::Common::DYNAMIC_FILE_UPLOAD> set, the body is a callback over
a queue of parts that it consumes destructively, so a second send streams zero
bytes under the original C<Content-Length> -- an empty file written with no
error anywhere. It is also why this is a function rather than an
L<LWP::UserAgent> subclass: a subclass would re-issue the same object.

Options:

=over 4

=item C<what>

Names the operation in the retry log line.

=item C<idempotent_only>

Retry only C<NEVER_SENT> failures. For callers whose operation cannot tolerate
being performed twice.

=item C<max_elapsed>

Wall-clock budget, defaulting to L</default_max_elapsed>.

=item C<on_retry>

Called as C<< $on_retry->(%info) >> before each wait, with C<what>, C<attempt>,
C<delay>, C<class> and C<response>. The default logs one line to STDERR; pass a
code ref to redirect it, or C<sub {}> to silence it.

=item C<send>

Overrides how a request is issued (default C<< $ua->request($req) >>). For
tests, and for callers that need C<< $ua->request($req, $content_cb) >>.

=item C<sleeper>, C<now>

Injectable clock and sleep, so the backoff can be tested in milliseconds.

=back

=cut

sub retry_request
{
    my($ua, $make_request, %opts) = @_;

    ref($make_request) eq 'CODE'
	or die "P3ClientUA::retry_request needs a code ref that builds a fresh request; " .
	       "an HTTP::Request cannot be replayed safely (see the POD)\n";

    my $what = $opts{what} // 'request';
    my $idempotent_only = $opts{idempotent_only} ? 1 : 0;
    my $max_elapsed = defined($opts{max_elapsed}) ? $opts{max_elapsed} : default_max_elapsed();
    my $now = $opts{now} || sub { time() };
    my $sleeper = $opts{sleeper} || sub { select(undef, undef, undef, $_[0]) };
    my $send = $opts{send} || sub { $_[0]->request($_[1]) };
    my $on_retry = exists $opts{on_retry} ? $opts{on_retry} : \&_log_retry;

    my $start = $now->();
    my $attempt = 0;
    my $res;

    while (1)
    {
	$res = $send->($ua, $make_request->());

	my $class = classify_response($res);

	return $res if $class eq NO_RETRY;
	return $res if retry_disabled();
	return $res if $idempotent_only && $class eq MAYBE_SENT;

	my $delay = backoff_delay($attempt);

	#
	# An explicit Retry-After outranks our guess, but only upward: the
	# service knowing better than us is the point, and honoring a shorter
	# one would let a busy edge talk us out of backing off.
	#
	if (defined(my $after = retry_after_seconds($res)))
	{
	    $delay = $after if $after > $delay;
	}

	#
	# Stop when the wait would take us past the budget rather than after it
	# already has: sleeping into a deadline we know we will miss just makes
	# the caller wait longer for the same failure.
	#
	last if ($now->() - $start) + $delay > $max_elapsed;

	$attempt++;

	$on_retry->(what => $what, attempt => $attempt, delay => $delay,
		    class => $class, response => $res) if $on_retry;

	$sleeper->($delay);
    }

    #
    # Budget exhausted. Hand back the last failure and let the caller report it
    # as it always has; the retry log above is where the effort is visible.
    #
    return $res;
}

sub _log_retry
{
    my(%info) = @_;

    my $res = $info{response};
    my $status = $res ? $res->status_line : 'no response';

    my @t = gmtime();
    my $ts = sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
		     $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0]);

    printf STDERR "%s: retrying %s in %.1fs (attempt %d, %s): %s\n",
	$ts, $info{what}, $info{delay}, $info{attempt}, $info{class}, $status;
}

1;
