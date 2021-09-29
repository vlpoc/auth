# Auth

The Authenticator (authsrv) is responsible for authenticating clients (actors).
AuthSrv may serve multiple domains.

## Actors

An actor is any user, service, or other kind of agent which may perform actions
or provide services in the system. An actor has a name, a domain, and an
authenticator.

* name - Simple name of the actor, can be thought of as the user name.
* domain - Optional field providing namespaces for actor names. This does not
need to be a domain in the DNS sense, but rather can be any string. For
instance, an administrator may choose to keep human users in the "users" domain
and service actors in the "service" domain.
* authenticator - This is a connection string (usually host:port) to the
authsrv for which the actor is valid. Users and services can keep a list of
authenticators that they accept Actors from, and use the `authenticator` field
to communicate with the authsrv to validate credentials.

Name and Domain may *not* contain the `/` or `@` characters, as these are used
as separators in the actor string. All other UTF-8 characters are valid in
every field. The authenticator may contain an arbitrary connection string,
which any client or server must understand. It is up to individual clients and
servers what kind of connection strings they accept, but (host:port) is common.

### Actor String
An actor can be represented as a human-readable string, according to the
following rules:
* The actor string begins with the 'name'.
* If the actor has a domain, it is added to the actor string after a '/' (i.e.
`name/domain')
* If the actor has specified an authenticator, it is added to the actor string
after a '@' (i.e. 'name/domain@authenticator')

In other words, the following actor forms are possible:
* name
* name/domain
* name@authenticator
* name/domain@authenticator

While it is possible to have an actor without an authenticator, actor objects
are not useful until they have been authenticated, at which point they will
have an authenticator field.

### Keys

While the Athenticator is designed to support multiple authentication
protocols, currently only one is implemented, called RSA-CERT. To authenticate
using RSA-CERT, each actor must have an RSA private key, and the authsrv must
have the public key.

## Authentication

Authentication is performed over gRPC. The authsrv serves a gRPC service (Auth)
with the following definition:
```
service Auth {
	rpc Authenticate (stream AuthMsg) returns (stream AuthMsg);
}
```

The `Authenticate` procedure allows an Actor to authenticate with authsrv and
receive a certificate (AuthCert), proving that the holder of the AuthCert has
permission to authenticate as the actor. Simple protocol negotiation is
performed first and subsequent AuthMsg's are exchanged between the client and
server according to the selected protocol. Currently only RSA-CERT is
supported.

The AuthCert is valid for a certain period of time and may be renewed, but can
also be revoked at any time by the authsrv.

### Protocol Negotiation
The first step of authentication is protocol negotiation. The authsrv will send
an AuthMsg containing a set of Protocols it is willing to authenticate with.
The client responds with a BeginAuth message containing the protocol (proto) that
the client wants to authenticate with.

### RSA-CERT Protocol
The only currently supported protocol for authenticating is called RSA-CERT. It
uses RSA public-key pairs to mutually authenticate an actor with the authsrv as
well as the authsrv with the actor.

##### Protocol objects:
For full details, see github.com/vlpoc/auth/auth_rpc.proto

The protocol is fairly simple and works like this:
1. After receiving the BeginAuth message, the authsrv will send a RSAStart
message containing the required Authenticator string and a secure-random
16-byte nonce. The nonce prevents replay attacks in the client.
2. The client receives this RSAStart message and begins creating an RSAProof
message using the following method:
	1. Construct the desired Actor using the Authenticator string from the
	RSAStart message.
	1. Concatenate the nonce bytes to the end of the UTF-8 [actor
	string](actor_string). (actor_string + nonce)
	2. Hash these bytes using SHA512.
	3. Sign the hash using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5
	4. Create a new secure-random 16-byte nonce that the authsrv will use
	in the final AuthCert. This nonce prevents replay by any server posing as
	an authsrv.	
	5. Assemble an RSAProof with the Actor, new nonce and signature, and send it
	to the authsrv inside an AuthMsg.
3. The authsrv receives the AuthMsg and verifies the signature using the same
method as the client.
4. Assuming the signature matches, the authsrv creates, signs and sends an
AuthCert using the following method, similar to the one used by the client:
	1. Create a 64-bit unix timestamp (seconds elapsed since January 1,
	1970 UTC) and concatenate the 8 bytes (little endian) to the end of the UTF-8
	[actor string](actor_string). Follow that with the nonce sent by the client in
	the RSAProof message. Follow the nonce with the Actor's public key, serialized
	into PKCS #1, ASN.1 DER form.
	2. Hash these bytes using SHA512
	3. Sign the bytes using the authsrv's RSA key RSASSA-PKCS1-V1_5-SIGN
	from RSA PKCS #1 v1.5
	4. Create an AuthCert containing the Actor, timestamp, nonce, public key, and
	signature, and send it to the client inside an AuthMsg.
