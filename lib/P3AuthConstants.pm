package P3AuthConstants;

use constant        globus_token_url   => 'http://rast.nmpdr.org/goauth/token?grant_type=client_credentials';
use constant        globus_profile_url   => 'http://rast.nmpdr.org/users';

use constant	    trust_token_signers => qw(
					     http://rast.nmpdr.org/goauth/keys/E087E220-F8B1-11E3-9175-BD9D42A49C03
					     https://nexus.api.globusonline.org/goauth/keys
					     https://rast.nmpdr.org/goauth/keys
					     https://rast.nmpdr.org/goauth/keys/E087E220-F8B1-11E3-9175-BD9D42A49C03
					     https://user.alpha.patricbrc.org/public_key
					     https://user.beta.patricbrc.org/public_key
					     https://user.patricbrc.org/public_key);


use constant	    role_service_url => 'https://kbase.us/services/authorization/Roles';

use base 'Exporter';
our @EXPORT_OK = qw(globus_token_url globus_profile_url trust_token_signers role_service_url);
our %EXPORT_TAGS = ( 
		    globus => [ qw(globus_token_url globus_profile_url trust_token_signers) ],
		    kbase  => [ qw(role_service_url) ],
		   );
{
    my %seen;
    
    push @{$EXPORT_TAGS{all}},
    grep {!$seen{$_}++} @{$EXPORT_TAGS{$_}} foreach keys %EXPORT_TAGS;
}

1;

