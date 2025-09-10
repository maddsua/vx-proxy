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

## Spinning up an instance

First of all you'd need to have a compatible RADIUS-based AAA server. Refer to [the RADIUS section](./radius.md) to learn more.

After a AAA server is up and running the vx config file has to be updated with ip address(es) of the server as well as with a new RADIUS protocol secret. Refer to [the config section](./config.md) for more info on configuration options. By default the config is located at `/etc/vx-proxy/vx-proxy.yml`.

Make sure that desired proxy services have valid port ranges assigned to them. After the configuration step is done, vx can be started as a systemd service or it can be run as a command.

### Deployment target

It's best to deploy vx directly onto a VPS as it needs to see the original IP addresses of incoming connections. A more sophisticated docker network configuration could help with lifting this limitation, however I have no plans in doing that right now.

A binary Debian package is available in [Releases](https://github.com/maddsua/vx-proxy/releases)
