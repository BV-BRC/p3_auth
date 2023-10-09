package P3AuthToken;

=head1 P3AuthToken

This module defines a simple authorization token wrapper for
the PATRIC command line interface.

=cut

use strict;
use File::Spec;

my $have_config_simple;
eval {
    require Config::Simple;
    $have_config_simple = 1;
};

sub new
{
    my($class, %params) = @_;

    my $self = {
	token => $params{token},
	ignore_authrc => $params{ignore_authrc},
	ignore_environment => $params{ignore_environment},
    };

    $self = bless $self, $class;

    if (!$self->token && !$self->ignore_environment)
    {
	$self->initialize_token_from_environment();
    }
    
    if (!$self->token && !$self->ignore_authrc)
    {
	$self->initialize_token_from_files();
    }
    return $self;
}

sub initialize_token_from_environment
{
    my($self) = @_;

    for my $env (qw(P3_AUTH_TOKEN KB_AUTH_TOKEN))
    {
	my $val = $ENV{$env};
	if ($self->is_token($val))
	{
	    $self->token($val);
	    return $val;
	}
    }
}

sub initialize_token_from_files
{
    my($self) = @_;

    my $token_path = $self->get_token_path();

    if (open(my $fh, "<", $token_path))
    {
	my $token = <$fh>;
	chomp $token;
	if ($self->is_token($token))
	{
	    $self->token($token);
	    return $token;
	}
    }
}

=head3 is_token

    my $bool = $auth_token->is_token($str)

Returns true if the token string passed as an argument is syntactically
valid to be an authorization token.

Do a basic check for an expired token.

=cut

sub is_token
{
    my($self, $token) = @_;

    return 0 unless $token =~ /\bun=/;

    #
    # Check for expiry.
    #
    my($exp) = $token =~ /\bexpiry=(\d+)/;
    if ($exp)
    {
	if (time >= $exp)
	{
	    warn "Token is expired ($exp)\n";
	    return 0;
	}
    }
    return 1;
}

sub user_id
{
    my($self) = @_;

    my($user_id) = $self->{token} =~ /\bun=([^|]+)/;
    return $user_id;
}

sub signature
{
    my($self) = @_;

    my($sig) = $self->{token} =~ /\bsig=([^|]+)/;
    return $sig;
}

sub is_admin
{
    my($self) = @_;
    return $self->{token} =~ /\|scope=user\|/ &&
	$self->{token} =~ /\|roles=admin\|/;
}

sub expiry
{
    my($self) = @_;

    my($exp) = $self->{token} =~ /\bexpiry=(\d+)/;

    return $exp;
}

sub get_token_path
{
    my($self) = @_;
    
    my $home;
    
    if ($^O eq 'MSWin32')
    {
	#
	# Crib this from File::HomeDir
	#
	if ( exists $ENV{HOME} and $ENV{HOME} ) {
	    $home = $ENV{HOME};
	}
	
	# Do we have a user profile?
	if ( exists $ENV{USERPROFILE} and $ENV{USERPROFILE} ) {
	    $home = $ENV{USERPROFILE};
	}
	
	# Some Windows use something like $ENV{HOME}
	if ( exists $ENV{HOMEDRIVE} and exists $ENV{HOMEPATH} and $ENV{HOMEDRIVE} and $ENV{HOMEPATH} ) {
	    $home = File::Spec->catpath(
				       $ENV{HOMEDRIVE}, $ENV{HOMEPATH}, '',
				      );
	}
    }
    else
    {
	$home = $ENV{HOME};
    }

    my $token_path = File::Spec->catfile($home, ".patric_token");

    return $token_path;
}

sub token
{
    my($self, $val) = @_;
    if (defined($val))
    {
	$self->{token} = $val;
    }
    $self->{token};
}

sub ignore_authrc
{
    my($self, $val) = @_;
    if (defined($val))
    {
	$self->{ignore_authrc} = $val;
    }
    $self->{ignore_authrc};
}

sub ignore_environment
{
    my($self, $val) = @_;
    if (defined($val))
    {
	$self->{ignore_environment} = $val;
    }
    $self->{ignore_environment};
}

1;


