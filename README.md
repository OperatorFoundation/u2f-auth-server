# U2F Authentication Plugin for OpenVPN Server

This plugin enables U2F authentication for OpenVPN servers. It must be used in concert with the U2F authentication plugin for OpenVPN clients.

## Prerequisites

This plugin requires a specific version of OpenVPN which includes extensions to the plugin API to enable the capabilities necessary to use U2F for authentication.
You can find the branch of OpenVPN with this functionality here: https://github.com/OperatorFoundation/openvpn/tree/auth-plugin-tls-session

## Dependencies

Install libu2f-server

    apt install libu2f-server0 libu2f-server-dev

Install microhttpd

    apt install libmicrohttpd10 libmicrohttpd-dev

## Building

Check out source

    git clone https://github.com/OperatorFoundation/u2f-auth-server.git

Install U2F authentication backend

    cd u2f-auth-server/u2f-server
    cmake .
    make

Install U2F authentication plugin

    cd ..
    cmake .
    make

## Installing

You will need both the plugin library, libu2f_server.so, and the backend, u2f-server.

