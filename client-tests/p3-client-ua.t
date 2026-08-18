#
# Tests for P3ClientUA: the Cloudflare-block heuristic, and the guarantee that a
# diagnostic dump never prints a credential.
#
# These are offline; nothing here talks to a network.
#

use strict;
use warnings;
use Test::More tests => 40;

use FindBin;
use lib "$FindBin::Bin/../lib";

use HTTP::Request;
use HTTP::Response;
use HTTP::Headers;

BEGIN { use_ok('P3ClientUA'); }

#
# A Cloudflare 1010 page: the edge refused us over the user-agent.
#
sub cf_block_response
{
    my $body = <<'END';
<!DOCTYPE html><html><head><title>Access denied | www.patricbrc.org used Cloudflare to restrict access</title></head>
<body><h1>Access denied</h1><h2>Error 1010</h2>
<div class="cf-error-details">Cloudflare Ray ID: 8f2c1d4e5a6b7890</div></body></html>
END
    my $res = HTTP::Response->new(403, 'Forbidden',
				  HTTP::Headers->new('Server' => 'cloudflare',
						     'CF-Ray' => '8f2c1d4e5a6b7890-ORD',
						     'Content-Type' => 'text/html; charset=UTF-8'),
				  $body);
    return $res;
}

#
# What our own login service returns for a wrong password. It is proxied by
# Cloudflare, so it carries a CF-Ray -- but it is not a block, and must not be
# reported as one.
#
sub origin_401_response
{
    my $res = HTTP::Response->new(401, 'Unauthorized',
				  HTTP::Headers->new('Server' => 'cloudflare',
						     'CF-Ray' => 'abc123-ORD',
						     'Content-Type' => 'application/json; charset=utf-8'),
				  '{"message":"Invalid username, email, or password","error":{"status":401}}');
    return $res;
}

#
# The same rejection as served to a client that asked for JSON -- captured from
# www.patricbrc.org/api in August 2026. Content-Type is application/json, so the
# HTML heuristic does not apply; the structured markers are what identify it.
#
sub cf_block_json_response
{
    my $body = '{"title":"Error 1010: Access denied","status":403,'
	. '"detail":"The site owner has blocked access based on your browser\'s signature.",'
	. '"error_code":1010,"error_name":"browser_signature_banned",'
	. '"ray_id":"a2cb01bfa85fa599","cloudflare_error":true,"retryable":false}';

    return HTTP::Response->new(403, 'Forbidden',
			       HTTP::Headers->new('Server' => 'cloudflare',
						  'CF-Ray' => 'a2cb01bfa85fa599-ORD',
						  'Content-Type' => 'application/json; charset=utf-8'),
			       $body);
}

#
# And the terse third form, served as text/plain -- this is what the solr query
# path in P3DataAPI gets back from www.patricbrc.org.
#
sub cf_block_text_response
{
    return HTTP::Response->new(403, 'Forbidden',
			       HTTP::Headers->new('Server' => 'cloudflare',
						  'CF-Ray' => 'a2cb01bfa85fa599-ORD',
						  'Content-Type' => 'text/plain; charset=UTF-8'),
			       "error code: 1010");
}

#
# user_agent_string: which identity wins.
#
# Every case starts from a clean slate -- no env, no product, no FIG_Config --
# because in a real run any of the three may already be set.
#
sub with_clean_ua_state(&)
{
    my($code) = @_;

    local $ENV{P3_USER_AGENT};
    local $ENV{P3_CLIENT_PRODUCT};
    local $FIG_Config::p3_data_api_user_agent;
    local $P3ClientUA::product;
    local $P3ClientUA::product_version;

    delete $ENV{P3_USER_AGENT};
    delete $ENV{P3_CLIENT_PRODUCT};
    undef $FIG_Config::p3_data_api_user_agent;
    undef $P3ClientUA::product;
    undef $P3ClientUA::product_version;

    return $code->();
}

with_clean_ua_state {
    is(P3ClientUA::user_agent_string(), 'BV-BRC P3 Client', 'with nothing set, the built-in default is used');
    is(P3ClientUA::product_string(), undef, 'no product declared means no product string');
};

with_clean_ua_state {
    $FIG_Config::p3_data_api_user_agent = 'Site Configured Agent';
    is(P3ClientUA::user_agent_string(), 'Site Configured Agent', 'FIG_Config supplies the identity when nothing else does');
};

with_clean_ua_state {
    $FIG_Config::p3_data_api_user_agent = 'BV-BRC P3 Client';
    P3ClientUA::set_product('bvbrc-cli-perl');
    is(P3ClientUA::user_agent_string(), 'bvbrc-cli-perl',
       'a declared product outranks the site default (which is set in every deployment)');
};

with_clean_ua_state {
    is(P3ClientUA::set_product('bvbrc-cli-perl', '1.2.3'), 'bvbrc-cli-perl/1.2.3', 'a version is appended with a slash');
    is(P3ClientUA::user_agent_string(), 'bvbrc-cli-perl/1.2.3', 'the versioned product is what goes on the wire');
};

with_clean_ua_state {
    P3ClientUA::set_product('bvbrc-cli-perl', '');
    is(P3ClientUA::user_agent_string(), 'bvbrc-cli-perl', 'an empty version leaves a bare product name, not a trailing slash');
};

with_clean_ua_state {
    #
    # This is how the generated p3-* wrappers identify the CLI: no script has
    # to call set_product.
    #
    $ENV{P3_CLIENT_PRODUCT} = 'bvbrc-cli-perl/9.9.9';
    is(P3ClientUA::user_agent_string(), 'bvbrc-cli-perl/9.9.9', 'P3_CLIENT_PRODUCT declares the product from outside the process');

    P3ClientUA::set_product('something-else');
    is(P3ClientUA::user_agent_string(), 'something-else',
       'an explicit set_product beats an inherited P3_CLIENT_PRODUCT');
};

with_clean_ua_state {
    $ENV{P3_CLIENT_PRODUCT} = '   ';
    is(P3ClientUA::user_agent_string(), 'BV-BRC P3 Client', 'a blank P3_CLIENT_PRODUCT is ignored');
};

with_clean_ua_state {
    $FIG_Config::p3_data_api_user_agent = 'Site Configured Agent';
    P3ClientUA::set_product('bvbrc-cli-perl', '1.2.3');
    $ENV{P3_USER_AGENT} = 'libwww-perl/6.67';
    is(P3ClientUA::user_agent_string(), 'libwww-perl/6.67',
       'P3_USER_AGENT is the escape hatch and outranks everything');
};

with_clean_ua_state {
    #
    # The agent string becomes a header value and comes from the environment,
    # so a newline in it would be header injection rather than a typo.
    #
    $ENV{P3_USER_AGENT} = "bad\r\nX-Injected: yes";
    unlike(P3ClientUA::user_agent_string(), qr/[\r\n]/, 'control characters are stripped from the agent string');
};

with_clean_ua_state {
    P3ClientUA::set_product('bvbrc-cli-perl', '1.2.3');
    is(P3ClientUA::new_ua()->agent, 'bvbrc-cli-perl/1.2.3', 'new_ua carries the product identity');
};

#
# is_cloudflare_block
#
ok(P3ClientUA::is_cloudflare_block(cf_block_response()), 'a 1010 block page is a Cloudflare block');
ok(P3ClientUA::is_cloudflare_block(cf_block_json_response()), 'a 1010 rejection served as JSON is a Cloudflare block');
ok(P3ClientUA::is_cloudflare_block(cf_block_text_response()), 'a 1010 rejection served as text/plain is a Cloudflare block');
ok(!P3ClientUA::is_cloudflare_block(origin_401_response()), 'an origin 401 with a CF-Ray is not a block');
ok(!P3ClientUA::is_cloudflare_block(HTTP::Response->new(200, 'OK', undef, 'fine')), 'a success is not a block');
ok(!P3ClientUA::is_cloudflare_block(HTTP::Response->new(500, 'Internal Server Error',
							HTTP::Headers->new('Content-Type' => 'application/json'),
							'{"error":"database is down"}')),
   'an origin 500 is not a block');
ok(P3ClientUA::is_cloudflare_block(HTTP::Response->new(403, 'Forbidden',
						       HTTP::Headers->new('CF-Mitigated' => 'challenge'), '')),
   'CF-Mitigated alone is a block');
ok(!P3ClientUA::is_cloudflare_block(undef), 'undef is not a block');

#
# http_failure_message
#
my $msg = P3ClientUA::http_failure_message(cf_block_response(), "Login");
like($msg, qr/^Login failed/, 'block message names the operation');
like($msg, qr/403/, 'block message carries the status');
like($msg, qr/blocked by Cloudflare/, 'block message names Cloudflare');
like($msg, qr/1010/, 'block message carries the error number');
like($msg, qr/user-agent not allowed/, 'block message explains 1010');
like($msg, qr/CF-Ray 8f2c1d4e5a6b7890-ORD/, 'block message carries the Ray id support asks for');

my $json_msg = P3ClientUA::http_failure_message(cf_block_json_response(), "Query");
like($json_msg, qr/blocked by Cloudflare/, 'JSON block message names Cloudflare');
like($json_msg, qr/error 1010/, 'JSON block message carries the error number');

my $text_msg = P3ClientUA::http_failure_message(cf_block_text_response(), "Query");
like($text_msg, qr/blocked by Cloudflare/, 'text/plain block message names Cloudflare');
like($text_msg, qr/error 1010/, 'text/plain block message carries the error number');

my $auth_msg = P3ClientUA::http_failure_message(origin_401_response(), "Login");
unlike($auth_msg, qr/blocked by Cloudflare/, 'a wrong password is not reported as a Cloudflare block');
like($auth_msg, qr/Invalid username/, 'the service message is quoted');
like($auth_msg, qr/CF-Ray abc123-ORD/, 'the Ray id is reported even when it is not a block');

#
# dump_http_failure: the redaction guarantee. login_rast puts the password in a
# Basic Authorization header, so a leak here is a leak of the password.
#
my $req = HTTP::Request->new(POST => 'https://user.patricbrc.org/authenticate',
			     HTTP::Headers->new('Content-Type' => 'application/x-www-form-urlencoded',
						'User-Agent' => 'BV-BRC P3 Client'),
			     'username=someone&password=hunter2');
$req->authorization_basic('someone', 'hunter2');

my $res = cf_block_response();
$res->header('Set-Cookie' => '__cf_bm=secretcookievalue; path=/');
$res->request($req);

my $dump = '';
open(my $fh, '>', \$dump) or die "cannot open string filehandle: $!";
P3ClientUA::dump_http_failure($res, $fh);
close($fh);

unlike($dump, qr/hunter2/, 'the dump does not leak the password');
unlike($dump, qr/c29tZW9uZTpodW50ZXIy/, 'the dump does not leak the encoded Basic credential');
unlike($dump, qr/secretcookievalue/, 'the dump does not leak a cookie value');
like($dump, qr/redacted/, 'the dump says what it withheld');
like($dump, qr/CF-Ray/i, 'the dump carries the response headers');
