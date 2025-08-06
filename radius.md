# VX'es RADIUS controls

## AAA

Once VX receives a new client that it hasn't seen in a while, it sends an `Access-Request` radius packet.

**Access-Request** packet:

| Attribute | Role | Format | Example |
| --- | --- | --- | --- |
| rfc2865.UserName | Password auth user name | /[a-z0-9_-]{1,64}/i | maddsua |
| rfc2865.UserPassword | Password auth password | /.{1,64}/ | thiccthighssavelives |
| rfc5580.LocationData | User's original IP | `binary` | 46.211.87.21 |
| rfc2865.NASIPAddress | Proxy server's IPv4 address that the client is connecting to | `binary` | 1.1.1.1 |
| rfc2865.NASIPv6Address | Proxy server's IPv6 address that the client is connecting to | `binary` | 2606:4700:4700::1001 |
| rfc2865.NASPort | Proxy server's port that the client is connecting to | `integer` | 1080 |

A successful authorization will create a session with an expiration timer. Until the session is valid, no more radius auth requests would be made. Sessions can be revoced by RADIUS DAC sending a DM message.

Invalid credentials will create a cached miss-entry that will prevent users from spamming the same wrong credentials. That entry is usually stored for one minute or a similar short amount of time.

Session "speed" is controlled by a mechanism in which the data is divided into 32KB chunks. After a chunk is sent, the time is measured and a delay that's required to achieve the target speed is calculated. Which means, you can't really set the speed to anthing lower than 256Kbps as of now.

Expected **Access-Accept**:

| Attribute | Role | Format | Example |
| --- | --- | --- | --- |
| rfc2866.AcctSessionID | Accounting session UUID | `binary` | 28c74360-afe7-4990-8d43-e823a18a02c6 |
| rfc2865.FramedIPAddress | IP address to configure for a session | `binary` | 1.2.3.4 |
| rfc6911.FramedIPv6Address | IPv6 address to configure for a session | `binary` | 2606:4700:4700::1001 |
| rfc4372.ChargeableUserIdentity | Accountable user ID | `text/binary` | maddsua |
| rfc2865.SessionTimeout | max. session duration | `duration seconds` | 3600 |
| rfc2865.IdleTimeout | max. session idle time | `duration seconds` | 600 |
| rfc4679.MaximumDataRateDownstream | Session bandwidth limit RX (download) (`0` treated as no limit) | `integer` | 50_000_000 |
| rfc4679.MaximumDataRateUpstream | Session bandwidth limit TX (upload) (`0` treated as no limit) | `integer` | 5_000_000 |

Immediately after a successfull `Access-Request` vx will try to start session accounting. This is done by sending a following packet.

**Accounting-Request-Start** packet:

| Attribute | Role | Format | Example |
| --- | --- | --- | --- |
| rfc2866.AcctStatusType | Accounting request type | `binary` | `Start` |
| rfc2866.AcctSessionID | Session UUID | `binary` | 28c74360-afe7-4990-8d43-e823a18a02c6 |

A session would not actually start proxying any data until it gets the "green light" from accounting.
After multiple failed Accounting-Start attempts a session will be terminated.

Every few minutes vx checks the amount of data transferred by it's sessions and of it sees a positive change - an InterimUpdate accounting request will be sent.

**Accounting-Request-InterimUpdate** packet:

| Attribute | Role | Format | Example |
| --- | --- | --- | --- |
| rfc2866.AcctStatusType | Accounting request type | `binary` | `InterimUpdate` |
| rfc2866.AcctSessionID | Session UUID | `binary` | 28c74360-afe7-4990-8d43-e823a18a02c6 |
| rfc2866.AcctInputOctets | Downlink (RX) data delta | `integer` | 100500 |
| rfc2866.AcctOutputOctets | Uplink (TX) data delta | `integer` | 9000 |

A failed InterimUpdate attempt does not cause a session to be terminated, but it surely will make a mess in the logs!

When a session is being terminated for whatever reason, a `Accounting-Request-Stop` is being sent.

It's pretty much the same as `InterimUpdate` except for an additional twist - this one also indicates an end of a session.

So, it both reports any unaccounted data volume and lets the auth server know that this session is done.

**Accounting-Request-Stop** packet:

| Attribute | Role | Format | Example |
| --- | --- | --- | --- |
| rfc2866.AcctStatusType | Accounting request type | `binary` | `InterimUpdate` |
| rfc2866.AcctSessionID | Session UUID | `binary` | 28c74360-afe7-4990-8d43-e823a18a02c6 |
| rfc2866.AcctInputOctets | Downlink (RX) data delta | `integer` | 2599 |
| rfc2866.AcctOutputOctets | Uplink (TX) data delta | `integer` | 500 |

## DAC

To remotely control sessions a DAC service can be used. By sending one of the following packets to a vx-proxy server one can update or disconnect sessions.

Changing session params is done by sending a `CoA-Request` packet that includes the parameters that have to be changed.

**CoA-Request** packet:

| Attribute | Role | Format | Example |
| --- | --- | --- | --- |
| rfc2866.AcctSessionID | Session UUID | `binary` | 28c74360-afe7-4990-8d43-e823a18a02c6 |
| rfc2865.SessionTimeout | max. session duration | `duration seconds` | 3600 |
| rfc2865.IdleTimeout | max. session idle time | `duration seconds` | 600 |
| rfc4679.MaximumDataRateDownstream | Session bandwidth limit RX (download) (`0` treated as no limit) | `integer` | 50_000_000 |
| rfc4679.MaximumDataRateUpstream | Session bandwidth limit TX (upload) (`0` treated as no limit) | `integer` | 5_000_000 |

Depending on the result of an operation, vx will respond with either `CoA-ACK` or `CoA-NACK`.

To completely straight up NUKE a session from existence one must send a `DM` packet.

**Disconnect-Request** packet:

| Attribute | Role | Format | Example |
| --- | --- | --- | --- |
| rfc2866.AcctSessionID | Session UUID | `binary` | 28c74360-afe7-4990-8d43-e823a18a02c6 |

If a session is successfully terminated, `Disconnect-ACK` will be sent in confirmation, or `Disconnect-NAK` otherwise.
