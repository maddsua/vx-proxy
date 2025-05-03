# vx-proxy

A scalable RADIUS-controlled proxy service.

## RADIUS protocol

vx uses RADIUS by default instead of relying on config files and controls lists. That is a huge advantage for the systems that need dynamic authorization. This allows you to rotate credentials anytime using a centralized manager service. Kinda nice if you wanna do a bunch of testing with different usernames or something.

When a credentials key `username-password-proxy_addr-port` is seen for the first time by a vx instance, it will make a RADIUS request to authenticate the client.

A successful authorization will create a session with an expiration timer. Until the session is active, no more radius auth requests would be made. Sessions can be revoced by RADIUS DAC sending a DM message.

Invalid credentials will create a cached miss-entry that will prevent users from spamming the same wrong credentials. That entry is usually stored for one minute or a similar short amount of time.

### Access-Request

Attributes:

- `rfc2865.UserName` - Proxy user name (latin letters, numbes, dash- and underscores)
- `rfc2865.UserPassword` - Proxy user password (any alphanumeric characters)
- `rfc5580.LocationData` - Proxy user IP address (v4 or v6)
- `rfc2865.NASIPAddress` | `rfc3162.NASIPv6Address` - IP address of a NAS (proxy server) that is serving the proxy user
- `rfc2865.NASPort` - NAS proxy port (literally the TCP/UDP port that the user connects to)

Expects: `Access-Accept` with:

- `rfc2866.AcctSessionID` - Accounting session UUID
- `rfc4372.ChargeableUserIdentity` - Accountable user UUID
- `rfc2865.SessionTimeout` - max. session duration (defaults to `1 hour`)
- `rfc2865.IdleTimeout` - max. session idle time (defaults to `10 min`)
- `rfc4679.MaximumDataRateDownstream` - Session bandwidth limit RX (download) (`0` treated as no limit)
- `rfc4679.MaximumDataRateUpstream` - Session bandwidth limit TX (upload) (`0` treated as no limit)

#### Session bandwidth control

Session "speed" is controlled by a mechanism in which the data is divided into 32KB chunks. After a chunk is sent, the time is measured and a delay that's required to achieve the target speed is calculated. Which means, you can't really set the speed to anthing lower than 256Kbps as of now.

Attributes:
- `rfc4679.MaximumDataRateDownstream` - as mentioned in `Access-Request`
- `rfc4679.MaximumDataRateUpstream` - as mentioned in `Access-Request`

### Accounting-Request-Start

This request is sent immediately after a successful client authorization to indicate start of a new session.

Attributes:

- `rfc2866.AcctStatusType` - Accounting request type (`Start`)
- `rfc2866.AcctSessionID` - Session UUID

Expects: sucessful message exchange

A session would not actually start proxying any data until it gets the "green light" from accounting. After multiple failed requests a session will be dropped.

### Accounting-Request-Interim-Update

Every few minutes vx checks on the amount of data transferred by it's sessions and of it sees a positive change - an InterimUpdate accounting request will be sent.

Attributes:

- `rfc2866.AcctStatusType` - Accounting request type (`InterimUpdate`)
- `rfc2866.AcctSessionID` - Session UUID
- `rfc2866.AcctInputOctets` - Downstream (RX) data delta
- `rfc2866.AcctOutputOctets` - Upstream (TX) data delta

Expects: sucessful message exchange

### Accounting-Request-Stop

It's pretty much the same as `InterimUpdate` except for an additional twist - this one also indicates an end of a session.

So, it both reports any unaccounted data volume and lets the auth server know that this session is done.

Attributes:

- `rfc2866.AcctStatusType` - Accounting request type (`Stop`)
- `rfc2866.AcctSessionID` - Session UUID
- `rfc2866.AcctInputOctets` - Downstream (RX) data delta
- `rfc2866.AcctOutputOctets` - Upstream (TX) data delta

Expects: sucessful message exchange

### Disconnect-Request

This request is a part of the DAC mechanism, where a request is sent from an auth server to a proxy instance to, well, end a session.

Attributes:
- `rfc2866.AcctSessionID` - Session UUID

Returns:
- `Disconnect-ACK` - If a session was successfully disconnected
- `Disconnect-NAK` - otherwise

### CoA-Request

Also part of the DAC mechanism, but instead of straight up nuking a session this one allows you to update it's parameters.

Attributes:
- `rfc2866.AcctSessionID` - Session UUID
- `rfc2865.IdleTimeout` - Set session idle timeout (optional)
- `rfc4679.MaximumDataRateDownstream` - Set max download speed (optional)
- `rfc4679.MaximumDataRateUpstream` - Set max upload speed (optional)

Returns:
- `CoA-ACK` - If a session was successfully updated
- `CoA-NAK` - otherwise
