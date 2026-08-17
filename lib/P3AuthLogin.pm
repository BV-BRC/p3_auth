package P3AuthLogin;

use strict;
use LWP::UserAgent;
use JSON::PP;
use P3ClientUA;

my $patric_authentication_url = "https://user.patricbrc.org/authenticate";
my $rast_authentication_url = "http://rast.nmpdr.org/goauth/token?grant_type=client_credentials";

my $ua_timeout = 10;

=head1 PATRIC User Login Utilities

This module contains routines for obtaining authentication tokens
from either the PATRIC or RAST authentication services.

=head2 Utility Routines

=head3 login_patric

    $token = P3AuthLogin::login_patric($username, $password)

Create a PATRIC authentication token using the given username and password.

Dies on failure to log in.    

=cut

sub login_patric
{
    my($user, $pass) = @_;

    my $token;
    
    #
    # Trim the @patricbrc.org suffix if present.
    #
    
    $user =~ s/^\@patricbrc.org$//;

    my $content = { username => $user, password => $pass };

    my $ua = P3ClientUA::new_ua(timeout => $ua_timeout);
    my $res = $ua->post($patric_authentication_url,$content);
    if ($res->is_success)
    {
	$token = $res->content;
    }
    else
    {
	_fail($res, "Login");
    }

    return $token;
}

=head3 sulogin_patric

    $token = P3AuthLogin::sulogin_patric($username, $password, $target_user)

Create a PATRIC authentication token for the target user using the given username and password.
User must be an administrator.

Dies on failure to log in.    

=cut

sub sulogin_patric

{
    my($user, $pass, $target_user) = @_;

    my $token;
    
    #
    # Trim the @patricbrc.org suffix if present.
    #
    
    $user =~ s/^\@patricbrc.org$//;

    my $content = { username => $user, password => $pass, targetUser => $target_user };

    my $ua = P3ClientUA::new_ua(timeout => $ua_timeout);
    my $res = $ua->post("$patric_authentication_url/sulogin", $content);
    if ($res->is_success)
    {
	$token = $res->content;
    }
    else
    {
	_fail($res, "Login");
    }

    return $token;
}

=head3 refresh_patric_token

    $token = P3AuthLogin::refresh_patric_token($token)

Assuming L<$token> is still valid,  use the P3 user service to create
a refreshed longer-lived token.

=cut

sub refresh_patric_token
{
    my($token) = @_;

    my $ua = P3ClientUA::new_ua(timeout => $ua_timeout);
    my $res = $ua->get("$patric_authentication_url/refresh", "Authorization", $token);
    if ($res->is_success)
    {
	$token = $res->content;
    }
    else
    {
	_fail($res, "Refresh");
    }


}

=head3 login_rast

    $token = P3AuthLogin::login_rast($username, $password)

Create a RAST authentication token using the given username and password.

Dies on failure to log in.    

=cut

sub login_rast
{
    my($user, $pass) = @_;

    my $token;

    my $ua = P3ClientUA::new_ua(timeout => $ua_timeout);

    my $headers = HTTP::Headers->new;

    $headers->authorization_basic($user, $pass);

    my $res = $ua->get($rast_authentication_url, $headers->flatten);
    if ($res->is_success)
    {
	my $token_obj = decode_json($res->content);
	$token = $token_obj->{access_token};
    }
    else
    {
	_fail($res, "Login");
    }

    return $token;
}

#
# Report a failed authentication request and die.
#
# The message carries the status, and for a Cloudflare rejection the CF-Ray id
# that support needs; P3_DEBUG_HTTP=1 additionally dumps the full (redacted)
# headers. See L<P3ClientUA>.
#
sub _fail
{
    my($res, $what) = @_;

    P3ClientUA::dump_http_failure($res, \*STDERR) if P3ClientUA::debug_enabled();

    die P3ClientUA::http_failure_message($res, $what);
}

1;
