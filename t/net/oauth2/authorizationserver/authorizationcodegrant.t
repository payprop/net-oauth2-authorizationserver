#!perl

use strict;
use warnings;

use Test::Most;

use_ok( 'Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant' );

isa_ok(
    my $Grant = Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant->new(
    ),
    'Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant'
);

can_ok(
    $Grant,
    qw/
		clients
		has_clients
	/
);

done_testing();
