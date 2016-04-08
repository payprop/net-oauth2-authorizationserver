#!perl

use strict;
use warnings;

use Test::Most;

use_ok( 'Net::OAuth2::AuthorizationServer' );

isa_ok(
    my $Server = Net::OAuth2::AuthorizationServer->new(
    ),
    'Net::OAuth2::AuthorizationServer'
);

can_ok(
    $Server,
    qw/
		auth_code_grant
	/
);

done_testing();
