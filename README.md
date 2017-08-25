PATRIC3 authentication support

Authentication in the PATRIC system uses oauth style bearer tokens.

Current interface uses Bio::KBase::AuthToken. It is highly configurable, but is 
rarely configured. It also includes validation machinery, including a cache of signer keys.

Little of this is needed in normal usage. Thus we define a simple token object:

       use Bio::P3::AuthToken;

       my $token = Bio::P3::AuthToken->new();

There is a default search path for finding tokens:

1. P3_AUTH_TOKEN environment variable. Holds string of bearer token.

2. KB_AUTH_TOKEN environment variable. Holds string of bearer token.

3. 

Parameters to new:

	