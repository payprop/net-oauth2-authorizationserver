package Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant;

=head1 NAME

Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant - OAuth2 Authorization Code Grant

=head1 SYNOPSIS

  my $Grant = Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant->new(
    clients => {
      TrendyNewService => {
        client_secret => 'boo',
        scopes        => {
          "post_images" => 1,
          "annoy_friends" => 1,
        },
      },
    }
  );

  # verify a client against known clients
  my ( $is_valid,$error ) = $Grant->verify_client( $client_id,\@scopes );

  if ( ! $Grant->login_resource_owner ) {
    # resource owner needs to login
    ...
  }

  # have resource owner confirm scopes
  my $confirmed = $Grant->confirm_by_resource_owner( $client_id,\@scopes );

  # generate a token
  my $token = $Grant->token(
    $client_id,
    \@scopes,
    'auth',        # one of: auth, access, refresh
    $redirect_url, # optional
    $user_id,      # optional
  );

  # store the auth code
  $Grant->store_auth_code(
    $token,
    $client_id,
    $Grant->auth_code_ttl,
    $redirect_url,
    @scopes
  );

  # verify an auth code
  my ( $client,$error,$scope,$user_id ) = $Grant->verify_auth_code(
    $client_id,
    $client_secret,
    $auth_code,
    $redirect_url
  );

  # store access token
  $Grant->store_access_token(
    $client,
    $auth_code,
    $access_token,
    $refresh_token,
    $Grant->access_token_ttl,
    $scope,
    $old_refresh_token
  );

  # verify an access token
  my ( $is_valid,$error ) = $Grant->verify_access_token(
    $access_token,
    \@scopes,
    $refresh_token
  );

=head1 DESCRIPTION

This module implements the OAuth2 "Authorization Code Grant" flow as described
at L<http://tools.ietf.org/html/rfc6749#section-4.1>.

In its simplest form you can call the module with just a hashref of known clients
and the code will "just work" - however in doing this you will not be able to
run a multi process persistent OAuth2 authorization server as the known auth codes
(ACs) and access tokens (ATs) will not be shared between processes and will be lost
on a restart.

To use this module in a more realistic way you need to at a minimum implement
the following functions and pass them to the module:

  login_resource_owner
  confirm_by_resource_owner
  verify_client
  store_auth_code
  verify_auth_code
  store_access_token
  verify_access_token

These will be explained in more detail below, in L<REQUIRED FUNCTIONS>, and you
can also see the tests and examples included with this distribution. OAuth2
seems needlessly complicated at first, hopefully this module will clarify the
various steps and simplify the implementation.

If you would still like to use the module in an easy way, but also have ACs and
ATs persistent across restarts and shared between multi processes then you can
supply a jwt_secret. What you lose when doing this is the ability for tokens to
be revoked. You could implement the verify_auth_code and verify_access_token
methods to handle the revoking in your app. So that would be halfway between
the "simple" and the "realistic" way. L<CLIENT SECRET, TOKEN SECURITY, AND JWT>
has more detail about JWTs.

=head1 CONSTRUCTOR ARGUMENTS

The module takes several constructor options. To use the module in a realistic
way you need to pass several callbacks, documented in L<REQUIRED FUNCTIONS>, and
marked here with a *

=head2 clients

A hashref of client details keyed like so:

  clients => {
    $client_id => {
      client_secret => $client_secret
      scopes        => {
        eat       => 1,
        drink     => 0,
        sleep     => 1,
      },
    },
  },

Note the clients config is not required if you add the verify_client callback,
but is necessary for running the module in its simplest form (when there are
*no* callbacks provided)

=head2 jwt_secret

This is optional. If set JWTs will be returned for the auth codes, access, and
refresh tokens. JWTs allow you to validate tokens without doing a db lookup, but
there are certain considerations (see L<CLIENT SECRET, TOKEN SECURITY, AND JWT>)

=head2 auth_code_ttl

The validity period of the generated authorization code in seconds. Defaults to
600 seconds (10 minutes)

=head2 access_token_ttl

The validity period of the generated access token in seconds. Defaults to 3600
seconds (1 hour)

=head2 login_resource_owner *

A callback that tells the module if a Resource Owner (user) is logged in. See
L<REQUIRED FUNCTIONS>.

=head2 confirm_by_resource_owner *

A callback that tells the module if the Resource Owner allowed or disallowed
access to the Resource Server by the Client. See L<REQUIRED FUNCTIONS>.

=head2 verify_client *

A callback that tells the module if a Client is know and given the scopes is
allowed to ask for an authorization code. See L<REQUIRED FUNCTIONS>.

=head2 store_auth_code *

A callback to store the generated authorization code. See L<REQUIRED FUNCTIONS>.

=head2 verify_auth_code *

A callback to verify an authorization code. See L<REQUIRED FUNCTIONS>.

=head2 store_access_token *

A callback to store generated access / refresh tokens. See L<REQUIRED FUNCTIONS>.

=head2 verify_access_token *

A callback to verify an access token. See L<REQUIRED FUNCTIONS>.

=cut

use strict;
use warnings;

use Moo;
use Types::Standard qw/ :all /;
use Carp qw/ croak /;
use Mojo::JWT;
use MIME::Base64 qw/ encode_base64 decode_base64 /;
use Crypt::PRNG qw/ random_string /;
use Try::Tiny;
use Time::HiRes qw/ gettimeofday /;

# undocumented for Mojolicious::Plugin::OAuth2::Server
has 'legacy_args' => (
	is        => 'rw',
	required  => 0,
);

has 'jwt_secret' => (
	is        => 'ro',
	isa       => Str,
	required  => 0,
);

has 'auth_code_ttl' => (
	is        => 'ro',
	isa       => Int,
	required  => 0,
	default   => sub { 600 },
);

has 'access_token_ttl' => (
	is        => 'ro',
	isa       => Int,
	required  => 0,
	default   => sub { 3600 },
);

has [ qw/
	clients
	auth_codes
	access_tokens
	refresh_tokens
/ ] => (
	is        => 'ro',
	isa       => Maybe[HashRef],
	required  => 0,
	default   => sub { {} },
);

has [ qw/
	verify_client_cb
	store_auth_code_cb
	verify_auth_code_cb
	store_access_token_cb
	verify_access_token_cb
	login_resource_owner_cb
	confirm_by_resource_owner_cb
/ ] => (
	is        => 'ro',
	isa       => Maybe[CodeRef],
	required  => 0,
);

sub BUILD {
	my ( $self,$args ) = @_;

	if (
		# if we don't have a list of clients
		! $self->has_clients
		# we must know how to verify clients and tokens
		and (
			! $args->{verify_client_cb}
			and ! $args->{store_auth_code_cb}
			and ! $args->{verify_auth_code_cb}
			and ! $args->{store_access_token_cb}
			and ! $args->{verify_access_token_cb}
		)
	) {
		croak __PACKAGE__ . " requires either clients or overrides"
	}
}

sub has_clients { return keys %{ shift->clients // {} } ? 1 : 0 }

sub verify_client {
	_delegate_to_cb_or_private( 'verify_client',@_ );
}

sub store_auth_code {
	_delegate_to_cb_or_private( 'store_auth_code',@_ );
}

sub verify_auth_code {
	_delegate_to_cb_or_private( 'verify_auth_code',@_ );
}

sub store_access_token {
	_delegate_to_cb_or_private( 'store_access_token',@_ );
}

sub verify_access_token {
	_delegate_to_cb_or_private( 'verify_access_token',@_ );
}

sub login_resource_owner {
	_delegate_to_cb_or_private( 'login_resource_owner',@_ );
}

sub confirm_by_resource_owner {
	_delegate_to_cb_or_private( 'confirm_by_resource_owner',@_ );
}

sub verify_token_and_scope {
  my ( $self,%args ) = @_;

  my ( $refresh_token,$scopes_ref,$auth_header,$is_legacy_caller )
	= @args{qw/ is_refresh_token scopes auth_header /};

  my $access_token;

  if ( ! $refresh_token ) {
    if ( $auth_header ) {
      my ( $auth_type,$auth_access_token ) = split( / /,$auth_header );

      if ( $auth_type ne 'Bearer' ) {
        return ( 0,'invalid_request' );
      } else {
        $access_token = $auth_access_token;
      }
    } else {
      return ( 0,'invalid_request' );
    }
  } else {
    $access_token = $refresh_token;
  }
  
  return $self->verify_access_token(
	%args,
	access_token     => $access_token,
	scopes           => $scopes_ref,
	is_refresh_token => $refresh_token,
  );
}

sub _delegate_to_cb_or_private {

	my $method = shift;
	my $self   = shift;
	my %args   = @_;

	my $cb_method = "${method}_cb";
	my $p_method  = "_$method";

	if ( my $cb = $self->$cb_method ) {

		if ( my $obj = $self->legacy_args ) {
			# for older users of Mojolicious::Plugin::OAuth2::Server need to pass
			# the right arguments in the right order to each function
			for ( $method ) {

				/login_resource_owner|confirm_by_resource_owner|verify_client/ && do {
					return $cb->(
						$obj,@args{qw/ client_id scopes / }
					);
				};

				/store_auth_code/ && do {
					my @scopes = @{ $args{scopes} };
					return $cb->(
						$obj,@args{qw/ auth_code client_id expires_in redirect_uri / },@scopes
					);
				};

				/verify_auth_code/ && do {
					return $cb->(
						$obj,@args{qw/ client_id client_secret auth_code redirect_uri / }
					);
				};

				/store_access_token/ && do {
					return $cb->(
						$obj,@args{qw/ client_id auth_code access_token refresh_token expires_in scopes old_refresh_token / }
					);
				};

				/verify_access_token/ && do {
					return $cb->(
						$obj,@args{qw/ access_token scopes is_refresh_token / }
					);
				};
			}

		} else {
			return $cb->( %args );
		}

	} else {
		return $self->$p_method( %args );
	}
}

=head1 REQUIRED FUNCTIONS

These are the callbacks necessary to use the module in a more realistic way, and
are required to make the auth code, access token, refresh token, etc available
across several processes and persistent.

The examples below use monogodb (a db helper returns a MongoDB::Database object)
for the code that would be bespoke to your application - such as finding access
codes in the database, and so on. You can refer to the tests in t/ and examples
in examples/ in this distribution for how it could be done and to actually play
around with the code both in a browser and on the command line.

The examples below are also using a "mojo_controller" object within the args hash
passed to the callbacks - you can pass any extra keys/values you want within
the args hash so you can do the necessary things (e.g. logging) along with the
required args

=head2 login_resource_owner_cb

A callback to tell the module if the Resource Owner is logged in. You can pass
a hash of arguments should you need to do anything within the callback It should
return 1 if the Resource Owner is logged in, otherwise it should do the required
things to login the resource owner (e.g. redirect) and return 0:

  my $resource_owner_logged_in_sub = sub {
    my ( %args ) = @_;

	my $c = $args{mojo_controller};

    if ( ! $c->session( 'logged_in' ) ) {
      # we need to redirect back to the /oauth/authorize route after
      # login (with the original params)
      my $uri = join( '?',$c->url_for('current'),$c->url_with->query );
      $c->flash( 'redirect_after_login' => $uri );
      $c->redirect_to( '/oauth/login' );
      return 0;
    }

    return 1;
  };

Note that you need to pass on the current url (with query) so it can be returned
to after the user has logged in. You can see that the flash is in use here - be
aware that the default routes (if you don't pass them to module constructor) for
authorize and access_token are under /oauth/ so it is possible that the flash may
have a Path of /oauth/ - the consequence of this is that if your login route is
under a different path (likely) you will not be able to access the value you set in
the flash. The solution to this? Simply create another route under /oauth/ (so in
this case /oauth/login) that points to the same route as the /login route

=cut

sub _login_resource_owner { 1 }

=head2 confirm_by_resource_owner_cb

A callback to tell the module if the Resource Owner allowed or denied access to
the Resource Server by the Client. The args hash should contain the client id,
and an array reference of scopes requested by the client.

It should return 1 if access is allowed, 0 if access is not allowed, otherwise
it should call the redirect_to method on the controller and return undef:

  my $resource_owner_confirm_scopes_sub = sub {
    my ( %args ) = @_;

    my ( $obj,$client_id,$scopes_ref )
	  = @args{ qw/ mojo_controller client_id scopes / };

    my $is_allowed = $obj->flash( "oauth_${client_id}" );

    # if user hasn't yet allowed the client access, or if they denied
    # access last time, we check [again] with the user for access
    if ( ! $is_allowed ) {
      $obj->flash( client_id => $client_id );
      $obj->flash( scopes    => $scopes_ref );

      # we need to redirect back to the /oauth/authorize route after
      # confirm/deny by resource owner (with the original params)
      my $uri = join( '?',$obj->url_for('current'),$obj->url_with->query );
      $obj->flash( 'redirect_after_login' => $uri );
      $obj->redirect_to( '/oauth/confirm_scopes' );
    }

    return $is_allowed;
  };

Note that you need to pass on the current url (with query) so it can be returned
to after the user has confirmed/denied access, and the confirm/deny result is
stored in the flash (this could be stored in the user session if you do not want
the user to confirm/deny every single time the Client requests access). Also note
the caveat regarding flash and Path as documented above (L<login_resource_owner>)

=cut

sub _confirm_by_resource_owner { 1 }

=head2 verify_client_cb

Reference: L<http://tools.ietf.org/html/rfc6749#section-4.1.1>

A callback to verify if the client asking for an authorization code is known
to the Resource Server and allowed to get an authorization code for the passed
scopes.

The args hash should contain the client id, and an array reference of request
scopes. The callback should return a list with two elements. The first element
is either 1 or 0 to say that the client is allowed or disallowed, the second
element should be the error message in the case of the client being disallowed:

  my $verify_client_sub = sub {
    my ( %args ) = @_;

    my ( $obj,$client_id,$scopes_ref )
	  = @args{ qw/ mojo_controller client_id scopes / };

    if (
      my $client = $obj->db->get_collection( 'clients' )
        ->find_one({ client_id => $client_id })
    ) {
        foreach my $scope ( @{ $scopes_ref // [] } ) {

          if ( ! exists( $client->{scopes}{$scope} ) ) {
            return ( 0,'invalid_scope' );
          } elsif ( ! $client->{scopes}{$scope} ) {
            return ( 0,'access_denied' );
          }
        }

        return ( 1 );
    }

    return ( 0,'unauthorized_client' );
  };

=cut

sub _verify_client {
  my ( $self,%args ) = @_;

  my ( $client_id,$scopes_ref ) = @args{qw/ client_id scopes /};

  if ( my $client = $self->clients->{$client_id} ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {

        if ( ! exists( $self->clients->{$client_id}{scopes}{$scope} ) ) {
          return ( 0,'invalid_scope' );
        } elsif ( ! $self->clients->{$client_id}{scopes}{$scope} ) {
          return ( 0,'access_denied' );
        }
      }

      return ( 1 );
  }

  return ( 0,'unauthorized_client' );
}

=head2 store_auth_code_cb

A callback to allow you to store the generated authorization code. The args hash
should contain the client id, the auth code validity period in seconds, the Client
redirect URI, and a list of the scopes requested by the Client.

You should save the information to your data store, it can then be retrieved by
the verify_auth_code callback for verification:

  my $store_auth_code_sub = sub {
    my ( %args ) = @_;

    my ( $obj,$auth_code,$client_id,$expires_in,$uri,$scopes_ref ) = @_;
	  @args{qw/ mojo_controller auth_code client_id expires_in redirect_uri scopes / };

    my $auth_codes = $obj->db->get_collection( 'auth_codes' );

    my $id = $auth_codes->insert({
      auth_code    => $auth_code,
      client_id    => $client_id,
      user_id      => $obj->session( 'user_id' ),
      expires      => time + $expires_in,
      redirect_uri => $uri,
      scope        => { map { $_ => 1 } @{ $scopes_ref // [] } },
    });

    return;
  };

=cut

sub _store_auth_code {
  my ( $self,%args ) = @_;

  my ( $auth_code,$client_id,$expires_in,$uri,$scopes_ref ) =
	@args{qw/ auth_code client_id expires_in redirect_uri scopes / };

  return if $self->jwt_secret;

  $self->auth_codes->{$auth_code} = {
    client_id     => $client_id,
    expires       => time + $expires_in,
    redirect_uri  => $uri,
    scope         => { map { $_ => 1 } @{ $scopes_ref // [] } },
  };

  return 1;
}

=head2 verify_auth_code_cb

Reference: L<http://tools.ietf.org/html/rfc6749#section-4.1.3>

A callback to verify the authorization code passed from the Client to the
Authorization Server. The args hash should contain the client_id, the
client_secret, the authorization code, and the redirect uri.

The callback should verify the authorization code using the rules defined in
the reference RFC above, and return a list with 4 elements. The first element
should be a client identifier (a scalar, or reference) in the case of a valid
authorization code or 0 in the case of an invalid authorization code. The second
element should be the error message in the case of an invalid authorization
code. The third element should be a hash reference of scopes as requested by the
client in the original call for an authorization code. The fourth element should
be a user identifier:

  my $verify_auth_code_sub = sub {
    my ( %args ) = @_;

    my ( $obj,$client_id,$client_secret,$auth_code,$uri )
	  = @args{qw/ mojo_controller client_id client_secret auth_code redirect_uri / };

    my $auth_codes      = $obj->db->get_collection( 'auth_codes' );
    my $ac              = $auth_codes->find_one({
      client_id => $client_id,
      auth_code => $auth_code,
    });

    my $client = $obj->db->get_collection( 'clients' )
      ->find_one({ client_id => $client_id });

    $client || return ( 0,'unauthorized_client' );

    if (
      ! $ac
      or $ac->{verified}
      or ( $uri ne $ac->{redirect_uri} )
      or ( $ac->{expires} <= time )
      or ( $client_secret ne $client->{client_secret} )
    ) {

      if ( $ac->{verified} ) {
        # the auth code has been used before - we must revoke the auth code
        # and access tokens
        $auth_codes->remove({ auth_code => $auth_code });
        $obj->db->get_collection( 'access_tokens' )->remove({
          access_token => $ac->{access_token}
        });
      }

      return ( 0,'invalid_grant' );
    }

    # scopes are those that were requested in the authorization request, not
    # those stored in the client (i.e. what the auth request restriced scopes
    # to and not everything the client is capable of)
    my $scope = $ac->{scope};

    $auth_codes->update( $ac,{ verified => 1 } );

    return ( $client_id,undef,$scope,$ac->{user_id} );
  };

=cut

sub _verify_auth_code {
  my ( $self,%args ) = @_;

  my ( $client_id,$client_secret,$auth_code,$uri )
	= @args{qw/ client_id client_secret auth_code redirect_uri / };

  return $self->_verify_auth_code_jwt( %args ) if $self->jwt_secret;

  my ( $sec,$usec,$rand ) = split( '-',decode_base64( $auth_code ) );

  if (
    ! exists( $self->auth_codes->{$auth_code} )
    or ! exists( $self->clients->{$client_id} )
    or ( $client_secret ne $self->clients->{$client_id}{client_secret} )
    or $self->auth_codes->{$auth_code}{access_token}
    or ( $uri && $self->auth_codes->{$auth_code}{redirect_uri} ne $uri )
    or ( $self->auth_codes->{$auth_code}{expires} <= time )
  ) {

    if ( my $access_token = $self->auth_codes->{$auth_code}{access_token} ) {
      # this auth code has already been used to generate an access token
      # so we need to revoke the access token that was previously generated
      $self->_revoke_access_token( $access_token );
    }

    return ( 0,'invalid_grant' );
  } else {
    return ( 1,undef,$self->auth_codes->{$auth_code}{scope} );
  }

}

sub _verify_auth_code_jwt {
  my ( $self,%args ) = @_;

  my ( $client_id,$client_secret,$auth_code,$uri )
	= @args{qw/ client_id client_secret auth_code redirect_uri / };

  my $client = $self->clients->{$client_id}
    || return ( 0,'unauthorized_client' );

  return ( 0,'invalid_grant' )
    if ( $client_secret ne $client->{client_secret} );

  my $auth_code_payload;

  try {
    $auth_code_payload = Mojo::JWT->new( secret => $self->jwt_secret )
      ->decode( $auth_code );
  } catch {
    return ( 0,'invalid_grant' );
  };

  if (
    ! $auth_code_payload
    or $auth_code_payload->{type} ne 'auth'
    or $auth_code_payload->{client} ne $client_id
    or ( $uri && $auth_code_payload->{aud} ne $uri )
  ) {
    return ( 0,'invalid_grant' );
  }

  my $scope = $auth_code_payload->{scopes};

  return ( $client_id,undef,$scope,undef );
}

=head2 store_access_token_cb

A callback to allow you to store the generated access and refresh tokens. The
args hash should contain the client identifier as returned from the
verify_auth_code callback, the authorization code, the access token, the
refresh_token, the validity period in seconds, the scope returned from the
verify_auth_code callback, and the old refresh token,

Note that the passed authorization code could be undefined, in which case the
access token and refresh tokens were requested by the Client by the use of an
existing refresh token, which will be passed as the old refresh token variable.
In this case you should use the old refresh token to find out the previous
access token and revoke the previous access and refresh tokens (this is *not* a
hard requirement according to the OAuth spec, but i would recommend it).

The callback does not need to return anything.

You should save the information to your data store, it can then be retrieved by
the verify_access_token callback for verification:

  my $store_access_token_sub = sub {
    my ( %args ) = @_;

    my (
      $obj,$client,$auth_code,$access_token,$refresh_token,
      $expires_in,$scope,$old_refresh_token
    ) = @args{qw/
      mojo_controller client_id auth_code access_token
      refresh_token expires_in scopes old_refresh_token
    / };

    my $access_tokens  = $obj->db->get_collection( 'access_tokens' );
    my $refresh_tokens = $obj->db->get_collection( 'refresh_tokens' );

    my $user_id;

    if ( ! defined( $auth_code ) && $old_refresh_token ) {
      # must have generated an access token via refresh token so revoke the old
      # access token and refresh token (also copy required data if missing)
      my $prev_rt = $obj->db->get_collection( 'refresh_tokens' )->find_one({
        refresh_token => $old_refresh_token,
      });

      my $prev_at = $obj->db->get_collection( 'access_tokens' )->find_one({
        access_token => $prev_rt->{access_token},
      });

      # access tokens can be revoked, whilst refresh tokens can remain so we
      # need to get the data from the refresh token as the access token may
      # no longer exist at the point that the refresh token is used
      $scope //= $prev_rt->{scope};
      $user_id = $prev_rt->{user_id};

      # need to revoke the access token
      $obj->db->get_collection( 'access_tokens' )
        ->remove({ access_token => $prev_at->{access_token} });

    } else {
      $user_id = $obj->db->get_collection( 'auth_codes' )->find_one({
        auth_code => $auth_code,
      })->{user_id};
    }

    if ( ref( $client ) ) {
      $scope  = $client->{scope};
      $client = $client->{client_id};
    }

    # if the client has en existing refresh token we need to revoke it
    $refresh_tokens->remove({ client_id => $client, user_id => $user_id });

    $access_tokens->insert({
      access_token  => $access_token,
      scope         => $scope,
      expires       => time + $expires_in,
      refresh_token => $refresh_token,
      client_id     => $client,
      user_id       => $user_id,
    });

    $refresh_tokens->insert({
      refresh_token => $refresh_token,
      access_token  => $access_token,
      scope         => $scope,
      client_id     => $client,
      user_id       => $user_id,
    });

    return;
  };

=cut

sub _store_access_token {
  my ( $self,%args ) = @_;

  my (
    $c_id,$auth_code,$access_token,$refresh_token,
    $expires_in,$scope,$old_refresh_token
  ) = @args{qw/ client_id auth_code access_token refresh_token expires_in scopes old_refresh_token / };

  return if $self->jwt_secret;

  if ( ! defined( $auth_code ) && $old_refresh_token ) {
    # must have generated an access token via a refresh token so revoke the old
    # access token and refresh token and update the AUTH_CODES hash to store the
    # new one (also copy across scopes if missing)
    $auth_code = $self->refresh_tokens->{$old_refresh_token}{auth_code};

    my $prev_access_token = $self->refresh_tokens->{$old_refresh_token}{access_token};

    # access tokens can be revoked, whilst refresh tokens can remain so we
    # need to get the data from the refresh token as the access token may
    # no longer exist at the point that the refresh token is used
    $scope //= $self->refresh_tokens->{$old_refresh_token}{scope};

    $self->_revoke_access_token( $prev_access_token );
  }

  delete( $self->refresh_tokens->{$old_refresh_token} )
    if $old_refresh_token;

  $self->access_tokens->{$access_token} = {
    scope         => $scope,
    expires       => time + $expires_in,
    refresh_token => $refresh_token,
    client_id     => $c_id,
  };

  $self->refresh_tokens->{$refresh_token} = {
    scope         => $scope,
    client_id     => $c_id,
    access_token  => $access_token,
    auth_code     => $auth_code,
  };

  $self->auth_codes->{$auth_code}{access_token} = $access_token;

  return $c_id;
}

=head2 verify_access_token_cb

Reference: L<http://tools.ietf.org/html/rfc6749#section-7>

A callback to verify the access token. The args hash should contain the access
token, an optional reference to a list of the scopes and if the access_token is
actually a refresh token. Note that the access token could be the refresh token,
as this method is also called when the Client uses the refresh token to get a
new access token (in which case the value of the $is_refresh_token variable will
be true).

The callback should verify the access code using the rules defined in the
reference RFC above, and return false if the access token is not valid otherwise
it should return something useful if the access token is valid - since this
method is called by the call to $c->oauth you probably need to return a hash
of details that the access token relates to (client id, user id, etc).

In the event of an invalid, expired, etc, access or refresh token you should
return a list where the first element is 0 and the second contains the error
message (almost certainly 'invalid_grant' in this case)

  my $verify_access_token_sub = sub {
    my ( %args ) = @_;

    my ( $obj,$access_token,$scopes_ref,$is_refresh_token )
  	  = @args{qw/ mojo_controller access_token scopes is_refresh_token /};

    my $rt = $obj->db->get_collection( 'refresh_tokens' )->find_one({
      refresh_token => $access_token
    });

    if ( $is_refresh_token && $rt ) {

      if ( $scopes_ref ) {
        foreach my $scope ( @{ $scopes_ref // [] } ) {
          if ( ! exists( $rt->{scope}{$scope} ) or ! $rt->{scope}{$scope} ) {
            return ( 0,'invalid_grant' )
          }
        }
      }

      # $rt contains client_id, user_id, etc
      return $rt;
    }
    elsif (
      my $at = $obj->db->get_collection( 'access_tokens' )->find_one({
        access_token => $access_token,
      })
    ) {

      if ( $at->{expires} <= time ) {
        # need to revoke the access token
        $obj->db->get_collection( 'access_tokens' )
          ->remove({ access_token => $access_token });

        return ( 0,'invalid_grant' )
      } elsif ( $scopes_ref ) {

        foreach my $scope ( @{ $scopes_ref // [] } ) {
          if ( ! exists( $at->{scope}{$scope} ) or ! $at->{scope}{$scope} ) {
            return ( 0,'invalid_grant' )
          }
        }

      }

      # $at contains client_id, user_id, etc
      return $at;
    }

    return ( 0,'invalid_grant' )
  };

=cut

sub _verify_access_token {
  my ( $self,%args ) = @_;
  return $self->_verify_access_token_jwt( %args ) if $self->jwt_secret;

  my ( $access_token,$scopes_ref,$is_refresh_token )
	= @args{qw/ access_token scopes is_refresh_token /};

  if (
    $is_refresh_token
    && exists( $self->refresh_tokens->{$access_token} )
  ) {

    if ( $scopes_ref ) {
      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if (
          ! exists( $self->refresh_tokens->{$access_token}{scope}{$scope} )
          or ! $self->refresh_tokens->{$access_token}{scope}{$scope}
        ) {
          return ( 0,'invalid_grant' )
        }
      }
    }

    return $self->refresh_tokens->{$access_token}{client_id};
  }
  elsif ( exists( $self->access_tokens->{$access_token} ) ) {

    if ( $self->access_tokens->{$access_token}{expires} <= time ) {
      $self->_revoke_access_token( $access_token );
      return ( 0,'invalid_grant' )
    } elsif ( $scopes_ref ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if (
          ! exists( $self->access_tokens->{$access_token}{scope}{$scope} )
          or ! $self->access_tokens->{$access_token}{scope}{$scope}
        ) {
          return ( 0,'invalid_grant' )
        }
      }

    }

    return $self->access_tokens->{$access_token}{client_id};
  }

  return ( 0,'invalid_grant' )
}

sub _verify_access_token_jwt {
  my ( $self,%args ) = @_;

  my ( $access_token,$scopes_ref,$is_refresh_token )
	= @args{qw/ access_token scopes is_refresh_token /};

  my $access_token_payload;

  try {
    $access_token_payload = Mojo::JWT->new( secret => $self->jwt_secret )
      ->decode( $access_token );
  } catch {
    chomp;
    return ( 0,'invalid_grant' );
  };

  if (
    $access_token_payload
    && (
      $access_token_payload->{type} eq 'access'
      || $is_refresh_token && $access_token_payload->{type} eq 'refresh'
    )
  ) {

    if ( $scopes_ref ) {
      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if ( ! grep { $_ eq $scope } @{ $access_token_payload->{scopes} } ) {
          return ( 0,'invalid_grant' );
        }
      }
    }

    return $access_token_payload;
  }

  return 0;
}

sub _revoke_access_token {
  my ( $self,$access_token ) = @_;
  delete( $self->access_tokens->{$access_token} );
}

sub token {
  my ( $self,%args ) = @_;

  my ( $client_id,$scopes,$type,$redirect_url,$user_id )
	= @args{qw/ client_id scopes type redirect_uri user_id / };

  my $ttl = $type eq 'auth' ? $self->auth_code_ttl : $self->access_token_ttl;
  undef( $ttl ) if $type eq 'refresh';
  my $code;

  if ( ! $self->jwt_secret ) {
    my ( $sec,$usec ) = gettimeofday;
    $code = encode_base64( join( '-',$sec,$usec,rand(),random_string(30) ),'' );
  } else {
    $code = Mojo::JWT->new(
      ( $ttl ? ( expires => time + $ttl ) : () ),
      secret  => $self->jwt_secret,
      set_iat => 1,
      # https://tools.ietf.org/html/rfc7519#section-4
      claims  => {
        # Registered Claim Names
#        iss    => undef, # us, the auth server / application
#        sub    => undef, # the logged in user
        aud    => $redirect_url, # the "audience"
        jti    => random_string(32),

        # Private Claim Names
        user_id      => $user_id,
        client       => $client_id,
        type         => $type,
        scopes       => $scopes,
      },
    )->encode;
  }

  return $code;
}

=head1 PUTTING IT ALL TOGETHER

Having defined the above callbacks, customized to your app/data store/etc, you
can configuration the module:

  my $Grant = Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant->new(
    login_resource_owner      => $resource_owner_logged_in_sub,
    confirm_by_resource_owner => $resource_owner_confirm_scopes_sub,
    verify_client             => $verify_client_sub,
    store_auth_code           => $store_auth_code_sub,
    verify_auth_code          => $verify_auth_code_sub,
    store_access_token        => $store_access_token_sub,
    verify_access_token       => $verify_access_token_sub,
  );

=head1 EXAMPLES

There are more examples included with this distribution in the examples/ dir.
See examples/README for more information about these examples.

=head1 CLIENT SECRET, TOKEN SECURITY, AND JWT

The auth codes and access tokens generated by the module should be unique. When
jwt_secret is B<not> supplied they are generated using a combination of the
generation time (to microsecond precision) + rand() + a call to Crypt::PRNG's
random_string function. These are then base64 encoded to make sure there are no
problems with URL encoding.

If jwt_secret is set, which should be a strong secret, the tokens are created
with the L<Mojo::JWT> module and each token should contain a jti using a call
to Crypt::PRNG's random_string function. You can decode the tokens, typically
with L<Mojo::JWT>, to get the information about the client and scopes - but you
should not trust the token unless the signature matches.

As the JWT contains the client information and scopes you can, in theory, use
this information to validate an auth code / access token / refresh token without
doing a database lookup. However, it gets somewhat more complicated when you
need to revoke tokens. For more information about JWTs and revoking tokens see
L<https://auth0.com/blog/2015/03/10/blacklist-json-web-token-api-keys/> and
L<https://tools.ietf.org/html/rfc7519>. Ultimately you're going to have to use
some shared store to revoke tokens, but using the jwt_secret config setting means
you can simplify parts of the process as the JWT will contain the client, user,
and scope information (JWTs are also easy to debug: L<http://jwt.io>).

When using JWTs expiry dates will be automatically checked (L<Mojo::JWT> has this
built in to the decoding) and the hash returned from the call to ->oauth will
look something like this:

  {
    'iat'     => 1435225100,               # generation time
    'exp'     => 1435228700,               # expiry time
    'aud'     => undef                     # redirect uri in case of type: auth
    'jti'     => 'psclb1AcC2OjAKtVJRg1JjRJumkVTkDj', # unique

    'type'    => 'access',                 # auth, access, or refresh
    'scopes'  => [ 'list','of','scopes' ], # as requested by client
    'client'  => 'some client id',         # as returned from verify_auth_code
    'user_id' => 'some user id',           # as returned from verify_auth_code
  };

Since a call for an access token requires both the authorization code and the
client secret you don't need to worry too much about protecting the authorization
code - however you obviously need to make sure the client secret and resultant
access tokens and refresh tokens are stored securely. Since if any of these are
compromised you will have your app endpoints open to use by who or whatever has
access to them.

You should therefore treat the client secret, access token, and refresh token as
you would treat passwords - so hashed, salted, and probably encrypted. As with
the various checking functions required by the module, the securing of this data
is left to you. More information:

L<https://stackoverflow.com/questions/1626575/best-practices-around-generating-oauth-tokens>

L<https://stackoverflow.com/questions/1878830/securly-storing-openid-identifiers-and-oauth-tokens>

L<https://stackoverflow.com/questions/4419915/how-to-keep-the-oauth-consumer-secret-safe-and-how-to-react-when-its-compromis>

=head1 REFERENCES

=over 4

=item * L<http://oauth.net/documentation/>

=item * L<http://tools.ietf.org/html/rfc6749>

=back

=head1 SEE ALSO

L<Mojolicious::Plugin::OAuth2::Server> - A Mojolicious plugin using this module

L<Mojo::JWT> - encode/decode JWTs

=head1 AUTHOR

Lee Johnson - C<leejo@cpan.org>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. If you would like to contribute documentation
or file a bug report then please raise an issue / pull request:

    https://github.com/G3S/net-oauth2-authorizationserver

=cut

__PACKAGE__->meta->make_immutable;
