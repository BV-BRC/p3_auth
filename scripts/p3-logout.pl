=head1 Log out from PATRIC

    p3-logout [options] 

Log out from PATRIC.

=cut

use strict;
use LWP::UserAgent;
use Getopt::Long::Descriptive;
use Term::ReadKey;
use Data::Dumper;
use P3AuthToken;
use P3AuthLogin;

my $max_tries = 3;

my($opt, $usage) = describe_options("%c %o",
				    ['help|h', 'display usage information', { shortcircuit => 1 }]);
print($usage->text), exit 0 if $opt->help;

my $token = P3AuthToken->new(ignore_environment => 1);

my $token_path = $token->get_token_path();

if (-f $token_path) {
    unlink($token_path) || die "Could not delete login file $token_path: $!";
    print "Logged out of PATRIC.\n";
} else {
    print "You are already logged out of PATRIC.\n";
}
