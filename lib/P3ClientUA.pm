package P3ClientUA;

use strict;
use LWP::UserAgent;
use Exporter 'import';

our @EXPORT_OK = qw(new_ua user_agent_string set_product product_string debug_enabled
		    is_cloudflare_block http_failure_message dump_http_failure);

#
# The BV-BRC sites sit behind Cloudflare, which rejects some default library
# user-agents outright (error 1010). LWP's default is one of them, so every
# client in this tree must present an allowlisted agent string instead.
#
# This is the fallback identity, used by any client that has not said which
# product it is (see set_product).
#
our $default_user_agent = "BV-BRC P3 Client";

#
# The product making the request, e.g. "bvbrc-cli-perl", and its version.
#
# The version is deliberately not defined anywhere in this tree: stamping a
# release is a release-tooling job, and code that guesses a version is worse
# than code that reports none. When there is no version we send a bare product
# name, which is a legal (if uninformative) user agent.
#
our $product;
our $product_version;

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
L</new_ua> so it presents an allowlisted string. A client that wants to be
identifiable in its own right -- so an access log or a block can be attributed
to it rather than to "some Perl client" -- declares itself with
L</set_product>.

=item *

When a request is rejected, the interesting evidence (status, C<CF-Ray> id,
response headers) was being discarded. L</http_failure_message> folds the
essentials into the die message, and L</dump_http_failure> prints the full
exchange when diagnostics are enabled.

=back

Diagnostics are enabled by setting C<P3_DEBUG_HTTP> in the environment (the
C<--debug-http> flag on L<p3-login> does this for you).

=head2 Utility Routines

=head3 set_product

    P3ClientUA::set_product($name, $version)

Declare which product this process is, so its requests can be told apart from
every other Perl client in the tree. C<$version> is optional; pass it only if
something authoritative supplied it (a build stamp, a release tag), never a
guess.

    P3ClientUA::set_product("bvbrc-cli-perl", "1.2.3");   # bvbrc-cli-perl/1.2.3
    P3ClientUA::set_product("bvbrc-cli-perl");            # bvbrc-cli-perl

A product may also be declared from outside the process by setting
C<P3_CLIENT_PRODUCT> in the environment to the whole string; that is how the
generated C<p3-*> wrappers identify the CLI without every script having to say
so. An explicit call here beats the environment, since an inherited value may
have come from a parent process that is not this product.

=cut

sub set_product
{
    my($name, $version) = @_;

    $product = $name;
    $product_version = $version;

    return product_string();
}

=head3 product_string

    $string = P3ClientUA::product_string()

The product identity as it will appear in the user agent
(C<name/version>, or bare C<name> when no version was supplied), or undef if no
product has been declared.

=cut

sub product_string
{
    if (defined($product) && $product =~ /\S/)
    {
	my $str = _header_safe($product);
	if (defined($product_version) && $product_version =~ /\S/)
	{
	    $str .= "/" . _header_safe($product_version);
	}
	return $str;
    }

    my $env = $ENV{P3_CLIENT_PRODUCT};
    return _header_safe($env) if defined($env) && $env =~ /\S/;

    return undef;
}

=head3 user_agent_string

    $ua_string = P3ClientUA::user_agent_string()

The agent string to present to the BV-BRC services. In precedence order:

=over 4

=item 1.

The C<P3_USER_AGENT> environment variable. This is the human's escape hatch --
per-invocation and explicit, so it wins over everything.

=item 2.

The product identity, from L</set_product> or C<P3_CLIENT_PRODUCT>. A client
that says what it is knows better than a site-wide default.

=item 3.

C<$FIG_Config::p3_data_api_user_agent>, the site's default identity for clients
that have none of their own.

=item 4.

C<$default_user_agent>.

=back

Note that 1 and 2 outranking 3 is deliberate, and is a change from the original
ordering: C<p3_data_api_user_agent> is set in every deployment (to the stock
string), so anything ranked below it could never take effect -- which made
C<P3_USER_AGENT> look broken.

=cut

sub user_agent_string
{
    my $env = $ENV{P3_USER_AGENT};
    return _header_safe($env) if defined($env) && $env =~ /\S/;

    my $prod = product_string();
    return $prod if defined($prod);

    #
    # Read FIG_Config defensively; this module is in p3_auth, which does not
    # depend on p3_core, so FIG_Config may never have been loaded.
    #
    no strict 'refs';
    my $configured = ${"FIG_Config::p3_data_api_user_agent"};
    return _header_safe($configured) if defined($configured) && $configured =~ /\S/;

    return $default_user_agent;
}

#
# A user agent string becomes a header value, and these strings come from the
# environment. Strip the control characters that would let one inject a header,
# and trim: a stray newline out of a shell variable would otherwise be a
# request-splitting bug rather than a cosmetic one.
#
sub _header_safe
{
    my($str) = @_;

    return undef unless defined $str;

    $str =~ s/[\x00-\x1f\x7f]+/ /g;
    $str =~ s/^\s+//;
    $str =~ s/\s+$//;

    return $str;
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
