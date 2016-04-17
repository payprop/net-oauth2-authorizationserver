#!perl

use strict;
use warnings;

use Test::Most;
use Test::Exception;

use FindBin qw/ $Bin /;
use lib "$Bin";
use authorizationcodegrant_tests;

use_ok( 'Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant' );

my $Grant;

# undocumented legacy_args attribute for back compat
# in Mojolicious::Plugin::OAuth2::Server
foreach my $legacy_args ( 0,1 ) {

	isa_ok(
		$Grant = Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant->new(
			legacy_args => $legacy_args ? $Grant : 0,
			clients     => authorizationcodegrant_tests::clients(),

			# am passing in a reference to the modules subs to ensure we hit
			# the code paths to call callbacks
			( $legacy_args ? (
				verify_client_cb => sub { return Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant::_verify_client( shift,client_id => shift, scopes => shift ) },
				store_auth_code_cb => sub { return Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant::_store_auth_code( shift,auth_code => shift,client_id => shift,expires_in => shift,redirect_uri => shift,scopes => [ @_ ] ) },
				verify_auth_code_cb => sub { return Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant::_verify_auth_code( shift,client_id => shift,client_secret => shift, auth_code => shift, redirect_uri => shift ) },
				store_access_token_cb => sub { return Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant::_store_access_token( shift,client_id => shift,auth_code => shift,access_token => shift,refresh_token => shift,expires_in => shift,scopes => shift,old_refresh_token => shift ) },
				verify_access_token_cb => sub { return Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant::_verify_access_token( shift,access_token => shift,scopes => shift,is_refresh_token => shift ) },
				login_resource_owner_cb => sub { return Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant::_login_resource_owner( shift,client_id => shift,scopes => shift ) },
				confirm_by_resource_owner_cb => sub { return Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant::_confirm_by_resource_owner( shift,client_id => shift,scopes => shift ) },
			) : () ),


		),
		'Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant'
	);

	authorizationcodegrant_tests::run_tests( $Grant );
}

done_testing();
