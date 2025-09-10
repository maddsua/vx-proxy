# VX config file

The VX config file sets the base service options as well as default session options and more.

File format: `yml`

Acutal file examples can be found at [cmd/vx-proxy/vx-proxy.yml](./cmd/vx-proxy/vx-proxy.yml) or [/etc/vx-proxy/vx-proxy.yml](/etc/vx-proxy/vx-proxy.yml) after installing the package.

## Sections reference

### Global

####  >- auth

Configures AAA options such as auth serivces and sessions

##### >- auth -> radius

Options for the RADIUS AAA module

Properties:

| Key | Description | Type | Format |
| --- | --- | --- | --- |
| `auth_addr` | Sets RADIUS authentication server address | `string` | `ipaddr` or `ipaddr:port` |
| `acct_addr` | Sets RADIUS accounting server | `string` | `ipaddr` or `ipaddr:port` |
| `listen_dac` | Sets DAC's listen address. Please note that DAC is a local service running on VX that listens to incoming CoA and DM messages and updates it's sessions accordingly. The address is usually just 0.0.0.0 or a specific address assigned to the hos VX is sitting at. | `string` | `ipaddr` or `ipaddr:port` |
| `secret` | RADIUS secret token. Make sure it's actually a secret xD | `string` | |

##### >- auth -> session

Default session options. These options can be overriden by RADIUS packets that an authentication server is sending.

Properties:

| Key | Description | Type | Format |
| --- | --- | --- | --- |
| `timeout` | Session TTL in seconds | `string` | `30s` |
| `idle_timeout` | Time after which is a session remains idle it should be terminated | `string` | `15s` |
| `connection_limit` | Max number of simultaneous connections | `int` | |
| `actual_rate_rx` | Dynamic session bandwidth limit for downloads | `int` | `1000K`, `1M`, etc |
| `actual_rate_tx` | Dynamic session bandwidth limit for uploads | `int` | `1000K`, `1M`, etc |
| `minimum_rate_rx` | Minimal connection bandwidth for downloads | `int` | `1000K`, `1M`, etc |
| `minimum_rate_tx` | Minimal connection bandwidth for uploads | `int` | `1000K`, `1M`, etc |
| `maximum_rate_rx` | Maximal connection bandwidth for downloads | `int` | `1000K`, `1M`, etc |
| `maximum_rate_tx` | Maximal connection bandwidth for uploads | `int` | `1000K`, `1M`, etc |

#### >- services

Configures which services are run by VX

#### >- services -> http

Configures HTTP service inbound swarm.

Properties:

| Key | Description | Type | Format |
| --- | --- | --- | --- |
| `port_range` | Specifies what port range should the HTTP swarm take | `string` | `{first_port}-{last_port}` |
| `forward_enable` | Enables http forward proxying (request hopping). By default only tcp tunneling is enabled. | `boolean` | |

#### >- services -> socks

Configures SOCKS service inbound swarm.

Properties:

| Key | Description | Type | Format |
| --- | --- | --- | --- |
| `port_range` | Specifies what port range should the SOCKS swarm take | `string` | `{first_port}-{last_port}` |

#### >- services -> telemetry

Telemetry services provides a simple http endpoint that can be used to detect proxy service downtime or other issues. It is NOT compatible with OpenTelemetry.

Properties:

| Key | Description | Type | Format |
| --- | --- | --- | --- |
| `listen_addr` | Telemetry service listen address/port | `string` | `ipaddr` or `ipaddr:port` |

#### >- debug

Enables verbose logging (aka debug mode). Same as providing `-debug` command line argument.
