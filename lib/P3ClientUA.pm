package P3ClientUA;

use strict;
use LWP::UserAgent;
use Exporter 'import';

our @EXPORT_OK = qw(new_ua user_agent_string debug_enabled
		    is_cloudflare_block http_failure_message dump_http_failure);

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

1;
