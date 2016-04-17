#!perl

use strict;
use warnings;

use Test::Most;
use Test::Exception;

use FindBin qw/ $Bin /;
use lib "$Bin";
use passwordgrant_tests;

use_ok( 'Net::OAuth2::AuthorizationServer::PasswordGrant' );

my $Grant;

# undocumented legacy_args attribute for back compat
# in Mojolicious::Plugin::OAuth2::Server
foreach my $legacy_args ( 0,1 ) {

	isa_ok(
		$Grant = Net::OAuth2::AuthorizationServer::PasswordGrant->new(
			legacy_args => $legacy_args ? $Grant : 0,
			clients     => passwordgrant_tests::clients(),
			users       => passwordgrant_tests::users(),

			# am passing in a reference to the modules subs to ensure we hit
			# the code paths to call callbacks
			( $legacy_args ? (
				verify_user_password_cb => sub { return Net::OAuth2::AuthorizationServer::PasswordGrant::_verify_user_password( shift,client_id => shift,client_secret => shift, username => shift, password => shift, scopes => shift ) },
				store_access_token_cb => sub { return Net::OAuth2::AuthorizationServer::PasswordGrant::_store_access_token( shift,client_id => shift,auth_code => shift,access_token => shift,refresh_token => shift,expires_in => shift,scopes => shift,old_refresh_token => shift ) },
				verify_access_token_cb => sub { return Net::OAuth2::AuthorizationServer::PasswordGrant::_verify_access_token( shift,access_token => shift,scopes => shift,is_refresh_token => shift ) },
				login_resource_owner_cb => sub { return Net::OAuth2::AuthorizationServer::PasswordGrant::_login_resource_owner( shift,client_id => shift,scopes => shift ) },
				confirm_by_resource_owner_cb => sub { return Net::OAuth2::AuthorizationServer::PasswordGrant::_confirm_by_resource_owner( shift,client_id => shift,scopes => shift ) },
			) : () ),


		),
		'Net::OAuth2::AuthorizationServer::PasswordGrant'
	);

	passwordgrant_tests::run_tests( $Grant );
}

done_testing();
