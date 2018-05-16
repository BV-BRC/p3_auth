=head1 Display the name of the user currently logged in.

    p3-whoami

Display the name of the user currently logged in. 

=cut

use strict;
use Getopt::Long::Descriptive;
use Term::ReadKey;
use Data::Dumper;
use P3AuthToken;
use P3AuthLogin;

my $max_tries = 3;

my($opt, $usage) = describe_options("%c %o username",
				    ['logout|logoff', 'log out of PATRIC'],
				    ['status|whoami|s', 'display login status'],
				    ['rast', 'create a RAST login token'],
				    ['verbose|v', 'display debugging info'],
				    ['help|h', 'display usage information', { shortcircuit => 1 }]);
print($usage->text), exit 0 if $opt->help;

my $username = shift;

my $token = P3AuthToken->new(ignore_environment => 1);

my $token_path = $token->get_token_path();

my $token_str = $token->token();
    
if (!$token_str) {
    print "You are currently logged out of PATRIC.\n";
} else {
    my($token_user) = $token_str =~ /\bun=([^|]+)/;
    
    if ($token_user)
    {
	if ($token_user =~ /^(.*)\@patricbrc.org$/)
	{
	    print "You are logged in as PATRIC user $1\n";
	}
	else
	{
	    print "You are logged in as RAST user $token_user\n";
	}
    } else {
	die "Your PATRIC login token is improperly formatted. Please log out and try again.";
    }
}
