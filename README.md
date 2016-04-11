# NAME

Net::OAuth2::AuthorizationServer - Easier implementation of an OAuth2
Authorization Server

<div>

    <a href='https://travis-ci.org/G3S/net-oauth2-authorizationserver?branch=master'><img src='https://travis-ci.org/G3S/net-oauth2-authorizationserver.svg?branch=master' alt='Build Status' /></a>
    <a href='https://coveralls.io/r/G3S/net-oauth2-authorizationserver?branch=master'><img src='https://coveralls.io/repos/G3S/net-oauth2-authorizationserver/badge.png?branch=master' alt='Coverage Status' /></a>
</div>

# VERSION

0.03

# SYNOPSIS

    my $Server = Net::OAuth2::AuthorizationServer->new;

    my $Grant  = $Server->auth_code_grant(
        ...
    );

# DESCRIPTION

This module is the gateway to the various OAuth2 grant flows, as documented
at [https://tools.ietf.org/html/rfc6749](https://tools.ietf.org/html/rfc6749). You should see the various modules
within this distribution for the implementation and usage details on various
types of grant flows.

## auth\_code\_grant

OAuth Authorisation Code Grant as document at [http://tools.ietf.org/html/rfc6749#section-4.1](http://tools.ietf.org/html/rfc6749#section-4.1).

See [Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant](https://metacpan.org/pod/Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant).

## implicit\_grant

## resource\_owner\_password\_grant

## client\_grant

## extension\_grant

Not yet implemented.

# EXAMPLES

There are examples included with this distribution in the examples/ dir.
See examples/README for more information about these examples.

# REFERENCES

- [http://oauth.net/documentation/](http://oauth.net/documentation/)
- [http://tools.ietf.org/html/rfc6749](http://tools.ietf.org/html/rfc6749)

# SEE ALSO

[Mojolicious::Plugin::OAuth2::Server](https://metacpan.org/pod/Mojolicious::Plugin::OAuth2::Server) - A Mojolicious plugin using this module

# AUTHOR

Lee Johnson - `leejo@cpan.org`

# LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. If you would like to contribute documentation
or file a bug report then please raise an issue / pull request:

    https://github.com/G3S/net-oauth2-authorizationserver
