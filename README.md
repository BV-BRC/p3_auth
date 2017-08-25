PATRIC3 authentication support

Authentication in the PATRIC system uses oauth style bearer tokens.

# Basic token access

Current interface uses Bio::KBase::AuthToken. It is highly configurable, but is 
rarely configured. It also includes validation machinery, including a cache of signer keys.

Little of this is needed in normal usage. Thus we define a simple token object:

       use Bio::P3::AuthToken;

       my $token = Bio::P3::AuthToken->new();

There is a default search path for finding tokens:

1. P3_AUTH_TOKEN environment variable. Holds string of bearer token.

2. KB_AUTH_TOKEN environment variable. Holds string of bearer token.

3. File .patric_token in user's home directory

4. File .patric_config in user's home directory

5. File .kbase_config in user's home directory

This module does *not* attempt to retrieve a token based on username information or to perform validation. 
It is purely a lightweight mechanism for retrieving a token from the standard location.

## Parameters to new:

* token  
Initialize this token object with the given token string. Used
in services that have obtained a token by other means (e.g. 
HTTP headers) and need to create a token object.

* ignore_authrc  
Don't try to read any flat file for obtaining token data. Used
on backend services to ignore the execution environment of
the userid that happens to be running the service.

# Token validation

On the server side we need to validate client tokens. This is provided by the 
module Bio:P3::Auth::Validate module which exports the single function `validate(token-object)`.

# Token generation

There are several ways to generate new tokens.

1. Via one of the Globus-style token generation services. The original one was at globus.org but we do not
use that. The RAST project has one that allows RAST credentials to be generated.

2. Via the PATRIC user service. 

Each of these options has a module that encapsulates the code. 

`Bio::P3::Auth::PATRICLogin::login` takes a PATRIC username and password and generates a token.

`Bio::P3::Auth::RASTLogin::login` takes a RAST username and password and generates a token.

