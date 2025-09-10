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

Config reference can be found [here](./config.md)

It's best to deploy vx directly onto a VPS as it needs to see the original IP addresses of incoming connections. A debian binary package is available in [Releases](https://github.com/maddsua/vx-proxy/releases). Don't forget to change the config file to suit your needs.
