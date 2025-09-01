<img src="./vx-logo.svg" width="240px" />

# A scalable RADIUS-controlled proxy service.

**Goals, really briefly**

To create a transparent remotely-controlled, private and easy to deploy proxy service.

Because v2ray is cool but no way in hell I trust a bunch of dudes from a country that's known to do not so funni things on the web.

## Proxy protocols

### SOCKS 5

Features:
- ✅ `CONNECT` command
- ⏳ `BIND` command
- ⏳ `ASSOCIATE` command
- ⏳ UDP proxy
- ✅ IPv4/IPV6/DOMAIN address type support
- ✅ Password auth

### HTTP

Features:
- ✅ HTTP tunnelling (`CONNECT` method)
- ✅ Forward-proxying (`GET`,`POST`, etc.)
- ✅ Basic proxy auth (username/password)
- ⏳ TLS (HTTPS) proxy

## Deploying

The RADIUS protocol is used to control vx. Refer to [The RADIUS section](./radius.md) to learn more.

It's best to deploy vx directly onto a VPS as it needs to see the original IP addresses of incoming connections. A debian binary package is available in [Releases](https://github.com/maddsua/vx-proxy/releases). Don't forget to change the config file to suit your needs.

**Config file reference**

```yml
# the auth section sets the options for the authentication service, obviously
auth:
  # only RADIUS is available at the time
  radius:
    # this is the main auth/accounting server address
    auth_addr: localhost:1812
    # you can specify a different address for the accounting services or leave it empty, so that the auth_addr is used for both operations
    acct_addr: localhost:1813
    # this sets the local address for the DAC service; leave it empty to use the default radius-defined port (:3799)
    listen_dac: localhost:3799
    # your radius secret. DON"T FORGET TO CHANGE IT!
    secret: secret
# the services sections defines, well, services, duh
services:
  # your average not impressive http proxy
  http:
    # TCP port range or a single port number
    port_range: 8810-8819
  # your sub-par socks proxy
  socks:
    # TCP port range or a single port number
    port_range: 8820-8825
  # the telemetry is used to do health checks and stuff. Please refer to the telemetry.openapi.yaml
  telemetry:
    # the local address to start this service on
    listen_addr: localhost:1111

```

todo: update config reference
