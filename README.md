mcfd
====

mcfd is a proxy application that can be used to encrypt arbitrary TCP connections.

To do that two components (here called "Server" and "Client") are used. The client
listens for TCP connections and forwards them to the server. The server forwards
connections from the client to the actual TCP server.

Once a connection between client and server is established, the two components
perform a mutual authentication protocol and establish a random session key. This key
is then used to encrypt the communication between client and server.

A use case for mcfd could look like this:

          Untrusted Network (encrypted)
                        |
    +-------------+     v     +-------------+
    | mcfd-client |-----------| mcfd-server |
    +-------------+           +-------------+
           |                         |
           | Trusted Network (plain) |
           |< - - - - - - - - - - - >|
           |                         |
    +-------------+           +-------------+
    | tcp-client  |           | tcp-server  |
    +-------------+           +-------------+

mcfd should...

* encrypt communication between client and server
* authenticate communication between client and server
* provide forward secrecy

mcfd doesn't...

* provide security against local attackers
* support any kind of PKI infrastructure
* provide backwards compatibility. If I decide to change the protocol client and server
  need to be updated.

Warning
-------

The alert reader probably noticed the distinct lack of an "mcfd does" section. That's
because I'm not sure it actually does what it should do. mcfd is not ready for use. I'm
not an experienced programmer, I have no background in cryptography or computer security.
Since nobody who does has checked mcfd's code, it is likely to decrease security for you.

Compilation
-----------

I only tested mcfd on Linux and with GCC. You'll also need cmake 2.8 or later and
libseccomp. To compile it just run `make`. If everything goes well you'll find the mcfd
binary under `build/mcfd`.

Usage
-----

The mcfd binary can act as both server and client component. Here is mcfd's standard usage
message:

`Usage: mcfd [-f] [-s] [-4|-6] [-l <listen_addr>] [-k <key>] <listen_port> <dst_addr> <dst_port>`

The key used for authentication is read from stdin or specified with the `-k` flag. Unless
`-s` is specified, mcfd operates as client component.

When operating as the client `listen_addr` and `listen_port` specify where to listen for
connections from a regular TCP client. In server mode they determine where mcfd listens
for a connection from an mcfd client.

The `dst_addr` and `dst_port` parameters determine the mcfd server to connect to in client
mode and the actual TCP server in server mode.

The `-4` and `-6` flags tell mcfd to use IPv4 or IPv6 exclusively.

Finally, the optional `-f` flag tells mcfd to fork a new process for each connection.

A simple use case might look like this:

You have an HTTP Server running on port 80 and want to access it with your client's
webbrowser.
On the server you would type `mcfd -s -f -l <server_ip> 8080 127.0.0.1 80`.
On the client you would type `mcfd -f -l 127.0.0.1 8081 <server_ip> 8080`.
Then you can direct your browser to http://localhost:8081/ to communicate with the
webserver.

Tests
-----

You'll need cmocka and netcat6 to run the (incomplete) test suite. Just run `make test`.

Crypto
------

mcfd uses [SpongeWrap](http://sponge.noekeon.org/SpongeDuplex.pdf) for authentication and
encryption and [Curve25519](http://cr.yp.to/ecdh.html) for key exchange. The permutation
used for spongewrap is the [Keccak](http://keccak.noekeon.org/) permutation.

For random number generation mcfd relies exclusively on /dev/urandom for now.

I reused parts of the testing code from the Keccak code package. The Curve25519
implementation was written by Adam Langley and can be found
[here](https://github.com/agl/curve25519-donna).

Also, powered by Curve25519.

License
-------

mcfd is licensed under the GPLv3.

Why?
----

I needed the ECTS credits and found out that I had way too much time on my hands.
