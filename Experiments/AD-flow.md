```text
Windows service (client, domain account, no keytab)
        |
        | 1) Logon / outbound auth setup
        v
      LSASS / SSPI
        |
        | 2) AS exchange with AD KDC
        |    gets TGT for client service account
        v
   AD DC / KDC
        |
        | 3) TGS exchange for target SPN
        |    SPN = HTTP/linux-srv01.zegarnet.local
        |    gets service ticket for Apache
        v
      LSASS / SSPI
        |
        | 4) Builds AP-REQ
        |    wraps it in SPNEGO if using HTTP Negotiate
        v
HTTP Authorization: Negotiate <token>
        |
        v
Apache + mod_auth_gssapi
        |
        | 5) Unwrap SPNEGO, extract AP-REQ
        | 6) Use keytab to decrypt service ticket
        | 7) Use session key from ticket to verify authenticator
        v
   Access granted / denied
```

## 1. What the Windows service does with AD before it ever talks to Apache

Windows service is running as a domain account such as `svc_client_app`. It is not using a keytab. That means it relies on the normal Windows security stack:

* the service has a Windows logon session
* LSASS holds the Kerberos credentials for that logon session
* SSPI is the API layer the application uses to request Kerberos/Negotiate auth

So the application usually does **not** talk to the KDC directly. It asks SSPI for an outbound security context, and SSPI/LSASS handle the Kerberos work.

Conceptually this happens first:

```text
Service starts under DOMAIN\svc_client_app
        |
        v
Windows logon session is created
        |
        v
LSASS gets or can get Kerberos credentials for that identity
```

If the service already has a valid TGT in its logon session, great. If not, Windows obtains one as needed.

## 2. The AS exchange with AD

Before a service can get a ticket for Apache, it needs a TGT.

That is the AS exchange:

```text
Client identity: svc_client_app@zegarnet.LOCAL
Target: krbtgt/zegarnet.LOCAL
```

Very roughly:

```text
Windows service -> LSASS/SSPI -> AD KDC (AS-REQ)
AD KDC -> LSASS/SSPI           (AS-REP with TGT)
```

What comes back is:

* a **TGT**
* a **client/TGS session key**

The TGT is not for Apache. It is only for talking to the ticket-granting service on the KDC.

So after this step, Windows has a cached TGT for the client service account.

## 3. The TGS exchange for Apache

Now your service wants to call:

```text
HTTP/linux-srv01.zegarnet.local
```

SSPI/LSASS asks AD for a **service ticket** for that SPN.

```text
Windows service -> LSASS/SSPI -> AD KDC (TGS-REQ for HTTP/linux-srv01.zegarnet.local)
AD KDC -> LSASS/SSPI           (TGS-REP with service ticket)
```

At this point AD does something important:

* it looks up which AD account owns the SPN
* it uses that account’s current service key to seal the service ticket

That is why Apache needs the matching keytab. The keytab is Apache’s local copy of the long-term key AD used when issuing that ticket.

## 4. What the Windows service sends to Apache

Over HTTP, the service usually uses **Negotiate** auth. So the HTTP message looks like:

```http
GET /kerberos/ HTTP/1.1
Host: linux-srv01.zegarnet.local
Authorization: Negotiate <base64 token>
```

That `<base64 token>` is usually a **SPNEGO** token, and inside it is the Kerberos mechanism token, which contains the **AP-REQ**.

So the layers are:

```text
HTTP
  -> Authorization: Negotiate <SPNEGO blob>
      -> SPNEGO
          -> Kerberos AP-REQ
```

Your Windows service normally does **not** manually build this byte by byte. It asks SSPI to initialize a security context for the target SPN, and SSPI returns the token to place in the HTTP header.

## 5. What is inside the AP-REQ

The AP-REQ is the message that proves to Apache:

* “here is my service ticket for you”
* “and here is proof I currently know the session key tied to that ticket”

Conceptually it contains:

```text
AP-REQ
  pvno
  msg-type
  ap-options
  ticket
  authenticator
```

### `pvno`

Kerberos protocol version.

### `msg-type`

Indicates this is an AP-REQ.

### `ap-options`

Flags controlling behavior, such as mutual authentication request.

### `ticket`

This is the service ticket AD issued for:

```text
HTTP/linux-srv01.zegarnet.local
```

That ticket includes, in effect:

* client principal
* service principal
* ticket validity times
* session key for client<->service use
* authorization data, often including PAC-related information in AD environments

The ticket itself is encrypted for the **service**, not for the client.

### `authenticator`

This is the fresh proof object created by the client and encrypted with the **session key from the service ticket**.

It typically carries:

* client realm
* client principal
* current timestamp
* microseconds
* optional checksum
* optional subkey
* optional sequence number

This is what prevents replay of a stolen ticket blob by itself.

## 6. How Apache verifies the AP-REQ with its keytab

Apache with `mod_auth_gssapi` receives the Negotiate header and passes it into the GSSAPI stack.

That stack does this:

### Step A: unwrap SPNEGO

It extracts the Kerberos AP-REQ from the HTTP Negotiate token.

### Step B: inspect the service ticket

It sees which principal, enctype, and KVNO the ticket expects.

### Step C: consult the keytab

Apache’s GSSAPI stack reads the keytab and looks for a matching service key entry.

If the keytab has the right entry, it can decrypt the service ticket.

If it does not, authentication fails.

### Step D: recover the session key

Once the service ticket is decrypted, Apache gets the client/service session key from inside the ticket.

### Step E: verify the authenticator

Apache uses that session key to decrypt the authenticator.

Then it checks:

* does the client identity in the authenticator match the identity in the ticket?
* is the timestamp fresh enough?
* is this a replay?

If those checks pass, the client is authenticated.

So the service keytab is used only for the **ticket decryption** step. After that, the **session key** from the ticket is used to verify the authenticator.

## 7. The exact split of responsibilities

This is the most important mental model.

### Windows client service

Responsible for:

* having a valid logon identity
* getting a TGT from AD
* getting a service ticket for Apache
* building the authenticator
* sending the AP-REQ

It does **not** need Apache’s keytab.

### Apache

Responsible for:

* holding the service’s long-term key in its keytab
* decrypting the service ticket
* validating the authenticator
* optionally sending AP-REP if mutual auth is requested

It does **not** need the client’s password.

### AD

Responsible for:

* issuing the TGT to the client
* issuing the service ticket for Apache’s SPN
* sealing that service ticket using Apache’s service key

## 8. A more literal message flow

```text
1. Service starts as DOMAIN\svc_client_app
   |
   v
2. LSASS obtains/holds TGT for svc_client_app@zegarnet.LOCAL
   |
   v
3. Service wants HTTP/linux-srv01.zegarnet.local
   |
   v
4. LSASS sends TGS-REQ to AD using TGT
   |
   v
5. AD returns service ticket for HTTP/linux-srv01.zegarnet.local
   |
   v
6. SSPI builds AP-REQ:
      - includes service ticket
      - includes authenticator encrypted with ticket session key
   |
   v
7. HTTP Authorization: Negotiate <SPNEGO(AP-REQ)>
   |
   v
8. Apache unwraps token
   |
   v
9. Apache uses keytab to decrypt ticket
   |
   v
10. Apache gets session key from ticket
    |
    v
11. Apache uses session key to decrypt authenticator
    |
    v
12. Apache checks identity, time, replay
    |
    v
13. Success or failure
```

## 9. What changes if Apache uses a transition keytab

Only Apache’s decryption step changes.

If the ticket coming from AD is for the new KVNO, Apache can decrypt it with the new keytab entry.

If a client still presents an older cached service ticket, Apache may still decrypt it with the old entry.

Your Windows client service does not need to know that Apache has one or two entries. It just sends the service ticket and authenticator it has.

## 10. What the Windows service code usually does

At code level, a Windows client service usually does something like:

* acquire outbound credentials for `Negotiate` or `Kerberos`
* initialize security context for target SPN
* get an output token
* place that token in `Authorization: Negotiate ...`

So the application typically does not manipulate:

* TGTs
* service tickets
* AP-REQ fields

directly. SSPI handles them.

## 11. One subtle point: AP-REQ is not the whole HTTP auth header

The HTTP header carries a base64-encoded token.

That token is often:

```text
SPNEGO -> Kerberos AP-REQ
```

So if you inspect network traffic, the header is not just “raw AP-REQ bytes.” There is usually a negotiation wrapper around the Kerberos token.

## 12. In one sentence

Your Windows service uses its own AD identity to get a TGT and then a service ticket for Apache, SSPI packages that into an AP-REQ inside HTTP Negotiate, and Apache uses its keytab to decrypt the ticket and then the ticket’s session key to validate the authenticator.

If you want, I can draw the same flow again but annotated with the exact keys used at each step: “client long-term key,” “TGT session key,” “service long-term key from keytab,” and “client/service session key.”
