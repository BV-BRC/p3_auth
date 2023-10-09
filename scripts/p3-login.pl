=head1 Create a BV-BRC login token.

    p3-login [options] username

Create a BV-BRC login token, used with workspace operations. To use this script, specify your user name on
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
# Create a BV-BRC login token.
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
				    ['logout|logoff', 'log out of BV-BRC'],
				    ['status|whoami|s', 'display login status'],
				    ['rast', 'create a RAST login token'],
				    ['verbose|v', 'display debugging info'],
				    ['sudo=s', 'get a token for this user', { hidden => 1 }],
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
        print "You are currently logged out of BV-BRC.\n";
    } else {
	my($token_user) = $token_str =~ /\bun=([^|]+)/;

	if ($token_user)
	{
	    if ($token_user =~ /^(.*)\@patricbrc.org$/)
	    {
		print "You are logged in as BV-BRC user $1\n";
	    }
	    else
	    {
		print "You are logged in as RAST user $token_user\n";
	    }
        } else {
            die "Your BV-BRC login token is improperly formatted. Please log out and try again.";
        }
    }
}

if ($opt->logout) {
    if (-f $token_path) {
        unlink($token_path) || die "Could not delete login file $token_path: $!";
        print "Logged out of BV-BRC.\n";
    } else {
        print "You are already logged out of BV-BRC.\n";
    }
}

my $token;

if (! $opt->status && ! $opt->logout) {
    if (! $username) {
        die "A user name is required.\n";
    }

    for my $try (1..$max_tries)
    {
        my $password = get_pass();

	if (!defined($password))
	{
	    exit 1;
	}	    
	$token = perform_login($username, $password, $opt->sudo);
	last if $token;
    }

    die "Too many incorrect login attempts; exiting.\n" unless $token;

    my($user) = $token =~ /un=([^|]+)/;

    if ($opt->sudo)
    {
	#
	# For sudo, create a new user shell with P3_AUTH_TOKEN set to our new token.
	#
	$ENV{P3_AUTH_TOKEN} = $ENV{KB_AUTH_TOKEN} = $token;
	my $shell = $ENV{SHELL} // "/bin/bash";
	print STDERR "Starting shell with BV-BRC login environment for $user\nType \"exit\" to return to normal environment\n";
	system($shell);
    }
    else
    {
	open(T, ">", $token_path) or die "Cannot write token file $token_path: $!\n";
	print T "$token\n";
	# Protect the chmod with eval so it won't blow up in Windows.
	eval { chmod 0600, \*T; };
	close(T);
	
	print "Logged in with username $user\n";
    }
}

sub perform_login
{
    my($username, $password, $target_user) = @_;

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
	    if ($target_user)
	    {
		$token = P3AuthLogin::sulogin_patric($username, $password, $target_user);
	    }
	    else
	    {
		$token = P3AuthLogin::login_patric($username, $password);
	    }
	};
    }
    
    if ($token)
    {
	if ($token !~ /un=([^|]+)/)
	{
	    die "Token has unexpected format\n";
	}
    }
    else
    {
	print "Sorry, try again.\n";
    }
    return $token;
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
	    if (!defined($key))
	    {
		last;
	    }
            elsif (ord($key) == 127 || ord($key) == 8) {
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

