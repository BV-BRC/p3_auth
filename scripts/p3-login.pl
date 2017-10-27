=head1 Create a PATRIC login token.

    p3-login [options] username

Create a PATRIC login token, used with workspace operations. To use this script, specify your user name on
the command line as a positional parameter. You will be asked for your password.

The following command-line options are supported.

=over 4

=item logout

The current user is logged out. If this option is specified, the user name is not required.

=item status

Display the name of the user currently logged in. If this option is specified, the user name is not required.

=back

If the command-line option C<--logout> is specified, you will be logged out. In this case, the user name is not required.

=cut

#
# Create a PATRIC login token.
#

use strict;
use LWP::UserAgent;
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

if ($opt->verbose) {
    print "Token path is $token_path.\n";
}

if ($opt->status || $opt->verbose) {
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
}

if ($opt->logout) {
    if (-f $token_path) {
        unlink($token_path) || die "Could not delete login file $token_path: $!";
        print "Logged out of PATRIC.\n";
    } else {
        print "You are already logged out of PATRIC.\n";
    }
}

if (! $opt->status && ! $opt->logout) {
    if (! $username) {
        die "A user name is required.\n";
    }

    for my $try (1..$max_tries)
    {
        my $password = get_pass();

	perform_login($username, $password);
    }

    die "Too many incorrect login attempts; exiting.\n";
}

sub perform_login
{
    my($username, $password) = @_;

    my $token;
    if ($opt->rast)
    {
	eval {
	    $token = P3AuthLogin::login_rast($username, $password);
	};
    }
    else
    {
	#
	# the P3AuthLogin code does suffix trimming on the username.
	eval {
	    $token = P3AuthLogin::login_patric($username, $password);
	};
    }
    
    if ($token)
    {
	if ($token =~ /un=([^|]+)/)
	{
	    my $un = $1;
	    open(T, ">", $token_path) or die "Cannot write token file $token_path: $!\n";
	    print T "$token\n";
	    # Protect the chmod with eval so it won't blow up in Windows.
	    eval { chmod 0600, \*T; };
	    close(T);

	    print "Logged in with username $un\n";
	    exit(0);
	}
	else
	{
	    die "Token has unexpected format\n";
	}
    }
    else
    {
	print "Sorry, try again.\n";
    }
}

sub get_pass {
    if ($^O eq 'MSWin32')
    {
        $| = 1;
        print "Password: ";
        ReadMode('noecho');
        my $password = <STDIN>;
        chomp($password);
        print "\n";
        ReadMode(0);
        return $password;
    }
    else
    {
        my $key  = 0;
        my $pass = "";
        print "Password: ";
        ReadMode(4);
        while ( ord($key = ReadKey(0)) != 10 ) {
            # While Enter has not been pressed
            if (ord($key) == 127 || ord($key) == 8) {
                chop $pass;
                print "\b \b";
            } elsif (ord($key) < 32) {
                # Do nothing with control chars
            } else {
                $pass .= $key;
                print "*";
            }
        }
        ReadMode(0);
        print "\n";
        return $pass;
    }
}

