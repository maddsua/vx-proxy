# VX'es RADIUS controls

VX uses a slightly modified "flow" of a generic DSL AAA. It avoids introducing a custom RADIUS dictionary by repurposing some of the standard radius attributes. 

Please read this document before jumping into writing your own authentication server implementation or trying to use an already existing solution.

The core goal of using RADIUS here is to avoid reinventing a square wheel that isn't compatible with absolutely anything out there. At the same time, retaining a full logic compatibility with existing vendors is out of scope and is not considered as an objective.

Generally, the AAA workflow looks like this:

```
# Authenticating and authorizing a client
# This doesn't allow any data transfer until a session started through the accounting

NAS: Access-Request
	rfc2865.User-Name
	rfc2865.User-Password
	rfc2865.NAS-IP-Address OR rfc2865.NAS-IPv6-Address
	rfc2865.NAS-Port
	rfc2865.Framed-Route

AUTH: Access-Accept OR Access-Reject
	rfc2866.Acct-Session-ID
	rfc2865.Framed-IP-Address OR rfc6911.Framed-IPv6-Address
	rfc2865.Session-Timeout
	rfc2865.Idle-Timeout
	rfc4679.Actual-Data-Rate-Downstream
	rfc4679.Actual-Data-Rate-Upstream
	rfc4679.Minimum-Data-Rate-Downstream
	rfc4679.Minimum-Data-Rate-Upstream
	rfc4679.Maximum-Data-Rate-Downstream
	rfc4679.Maximum-Data-Rate-Upstream

# Starting a session

NAS: Accounting-Request
	rfc2866.Acct-Status-Type === Start
	rfc2866.Acct-Session-ID

ACCT: Accounting-Response

...

NAS: Accounting-Request
	rfc2866.Acct-Status-Type === Interim-Update
	rfc2866.Acct-Session-ID
	rfc2866.Acct-Input-Octets
	rfc2866.Acct-Output-Octets

ACCT: Accounting-Response

...

# Terminating a session

NAS: Accounting-Request
	rfc2866.Acct-Status-Type === Stop
	rfc2866.Acct-Session-ID
	rfc2866.Acct-Input-Octets
	rfc2866.Acct-Output-Octets

ACCT: Accounting-Response
```

As well as basic AAA VX also supports dynamic authentication stuff like updating session parameters and whatnot using RADIUS DAC, which has the following flow:

```

# Updating existing session connection speed

DAC: CoA-Request
	rfc2866.Acct-Session-ID
	rfc2865.Idle-Timeout
	rfc4679.Actual-Data-Rate-Downstream
	rfc4679.Actual-Data-Rate-Upstream

NAS: CoA-ACK OR CoA-NACK

...

# Terminating a session

DAC: Disconnect-Request
	rfc2866.Acct-Session-ID

NAS: Disconnect-ACK OR Disconnect-NAK
```

## Attribute details

To provide more details on how to control VX via RADIUS here's a complete list of used RADIUS attributes:

| Attribute | Description | Used in | Dynamic (can be updated with CoA) | Type |
| --- | --- | --- | --- | --- |
| `rfc2865.User-Name` | Plaintext username of a connecting user | `Access-Request` | | `string` |
| `rfc2865.User-Password` | Connecting user's password | `Access-Request` | | `secret` |
| `rfc2865.NAS-IP-Address` or `rfc2865.NAS-IPv6-Address` | Contains proxy's IP address that a client is trying to connect to | `Access-Request` | | `ipaddr` |
| `rfc2865.NAS-Port` | A tcp/udp port number that a user is connecting to on a proxy server | `Access-Request` | | `int` |
| `rfc2865.Framed-Route` | At this moment is only used to pass the original client's IP. Users the following format: `client_ip/{32\|128} 0.0.0.0`. For example: `127.0.0.1/32 0.0.0.0`. This is the artifact of the decisiong of not creating a custom dictionary | `Access-Request` | | `string` |
| `rfc2865.Framed-IP-Address` or `rfc6911.Framed-IPv6-Address` | Contains an IP address that VX must give to the user | `Access-Accept` | | `ipaddr` |
| `rfc2865.Session-Timeout` | Sets the amount of time in seconds after which a session much be terminated | `Access-Accept` | | `int` |
| `rfc2865.Idle-Timeout` | Sets the amount of time in seconds after which if a session haven't transferred any data it should be terminated | `Access-Accept`, `CoA-Request` | \+ | `int` |
| `rfc2865.Port-Limit` | Sets the max number of connections that a session can have | `Access-Accept`, `CoA-Request` | \+ | `int` |
| `rfc2865.rfc4679.Actual-Data-Rate-Downstream` | Sets dynamic connection speed limit for download streams. It is divided between all the active connections for a session | `Access-Accept`, `CoA-Request` | \+ | `int` |
| `rfc2865.rfc4679.Actual-Data-Rate-Upstream` | Sets dynamic connection speed limit for upload streams. It is divided between all the active connections for a session | `Access-Accept`, `CoA-Request` | \+ | `int` |
| `rfc2865.rfc4679.Minimum-Data-Rate-Downstream` | Sets the minimal connection download speed. If overrides the dynamically calculated bandwidth value if it's lower than this. It does nothing when dynamic bandwidth is not set or is overriden | `Access-Accept`, `CoA-Request` | \+ | `int` |
| `rfc2865.rfc4679.Minimum-Data-Rate-Upstream` | Sets the minimal connection upload speed. If overrides the dynamically calculated bandwidth value if it's lower than this. It does nothing when dynamic bandwidth is not set or is overriden | `Access-Accept`, `CoA-Request` | \+ | `int` |
| `rfc2865.rfc4679.Maximum-Data-Rate-Downstream` | Sets the maximal connection download speed. It overrides any dynamically calculated banwidth value that is higher than this | `Access-Accept`, `CoA-Request` | \+ | `int` |
| `rfc2865.rfc4679.Maximum-Data-Rate-Upstream` | Sets the maximal connection upload speed. It overrides any dynamically calculated banwidth value that is higher than this | `Access-Accept`, `CoA-Request` | \+ | `int` |
| `rfc2866.Acct-Session-ID` | Contains session UUID. First it's returned by `Access-Accept` packet. This ID must be used in all the following `Accounting-Request`s or DAC messages. | `Access-Accept`, `Accounting-Request`, `CoA-Request`, `Disconnect-Request` | | `string` (UUID) |
| `rfc2866.Acct-Status-Type` | Tells which accounting operation must be performed | `Accounting-Request` | | `enum` |
| `rfc2866.Acct-Input-Octets` | Total data volume downloaded by the client since the last update | `Accounting-Request` | | `int` |
| `rfc2866.Acct-Output-Octets` | Total data volume uploaded by the client since the last update | `Accounting-Request` | | `int` |

### Bandwidth controls

Since VX uses a mix of different radius attributes to control connection speed, these are the possible modes:

#### A: The proper way

Configuring `Actual-Data-Rate-*` attributes sets the total desired bandwidth over all the connections of each sessions. The actual connection speed is then determined dynamically based on active data usage.

However, in some cases it may be desirable to set a minimal possible connection speed, to, for example, ensure that no connection is getting slower than a certain threshold. Use `Minimum-Data-Rate-*` attributes to send lower bandwidth bound.

In other cases limiting the maximum connection speed may be desired. To override dynamic banwidth upper bound `Maximum-Data-Rate-*` attributes can be used.

#### B: Using only Maximum-Data-Rate-* limits

When setting only the upper connection speed, vx would fall back to the configured global values (config file) or the default values hardcoded in the config parser itself. By setting those default values to some high numbers one could then limit per-connection speed with `Maximum-Data-Rate-*` radius attributes.
