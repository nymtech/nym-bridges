# Sharing port 443 between nginx and nym-bridge

If `nginx` already terminates this node's own HTTPS on port 443 (a landing page, an `/api/`
proxy to `nym-node`, etc.), `add-stealth-ports.sh` will not touch it automatically - it skips the
TLS transport and points you here instead. This is the recipe that was used to do exactly this on
two real, already-serving-traffic gateways, with zero disruption to either the existing HTTPS or
the bridge's other transports.

## How it works

nginx's `stream` module can inspect a TLS ClientHello's SNI **without decrypting it**
(`ssl_preread`), then forward the connection's raw bytes to whichever backend you choose based on
that SNI. Your real domain goes to nginx's existing HTTPS vhost (moved to a loopback-only port);
everything else - including the bridge's disguise hostname - goes to `nym-bridge`, which also
only listens on loopback. Nothing is decrypted by the proxy; each backend still does its own real
TLS termination with its own certificate.

## Before you start

Check the stream module is available (it usually already is on Debian/Ubuntu, just not loaded):

```bash
nginx -V 2>&1 | grep -o with-compat    # must print "with-compat"
ls /usr/lib/nginx/modules/ | grep ngx_stream_module.so
dpkg -l | grep libnginx-mod-stream || apt-get install -y libnginx-mod-stream
ls /etc/nginx/modules-enabled/ | grep stream   # if this prints nothing, it isn't loaded yet
```

If the module isn't loaded, Debian/Ubuntu's package ships the directive already - you just need
the symlink:

```bash
ln -s /usr/share/nginx/modules-available/mod-stream.conf /etc/nginx/modules-enabled/50-mod-stream.conf
```

## Steps

Back up first:

```bash
cp /etc/nginx/nginx.conf /root/nginx.conf.bak
cp /etc/nginx/sites-enabled/<your-vhost-file> /root/<your-vhost-file>.bak
```

1. **Move your existing HTTPS vhost off the public port, onto loopback.** In the `server { listen
   443 ssl; ... }` block (and its `listen [::]:443 ssl;` line if present), replace both with a
   single loopback line - nothing else in that block changes:

   ```nginx
   listen 127.0.0.1:8443 ssl;
   ```

2. **Add a `stream` block** to `/etc/nginx/nginx.conf` (top level, alongside `http { ... }` - not
   inside it). Replace `<your-domain>`, `<public-ipv4>` and `<public-ipv6>` with your own:

   ```nginx
   stream {
       map $ssl_preread_server_name $bridge_upstream {
           <your-domain> 127.0.0.1:8443;
           default       127.0.0.1:443;
       }

       server {
           listen <public-ipv4>:443;
           listen [<public-ipv6>]:443;
           ssl_preread on;
           proxy_pass $bridge_upstream;
       }
   }
   ```

   The `listen` lines here **must** name your specific public IP addresses, not `443`/`[::]:443`
   on their own. A wildcard bind here would claim loopback too, and then `nym-bridge` could never
   bind `127.0.0.1:443` for the step below - this exact mistake caused a short real outage during
   initial testing, so it's called out here deliberately.

3. **Check and apply:**

   ```bash
   nginx -t                   # must say "syntax is ok" / "test is successful" before continuing
   systemctl restart nginx    # use restart, not `nginx -s reload` - reload did not reliably
                               # rebind the new stream listen sockets in testing
   ```

4. **Verify nginx's own HTTPS still works** (from another machine, over the real internet, with
   the real domain's SNI):

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' https://<your-domain>/
   ```

   Expect `200` (or whatever your landing page normally returns). If this fails, restore the two
   backup files and `systemctl restart nginx` before doing anything else.

5. **Confirm loopback 443 is genuinely free**, then run `add-stealth-ports.sh` (or add the
   `tls_plain` transport by hand) with its `listen` set to `127.0.0.1:443` - loopback, same port
   number as the public one. The port number must match what you want published to clients; only
   the bind address differs.

   ```bash
   timeout 1 bash -c 'echo > /dev/tcp/127.0.0.1/443' && echo "still taken" || echo "free"
   ```

## Why the port number has to match

`nym-bridge` derives the address it publishes to clients directly from its own `listen` port -
there is no separate "advertised port" setting. If `nym-bridge` listens on `127.0.0.1:8444`, it
publishes `<your-public-ip>:8444` to clients, which is wrong (nothing external is listening
there). Binding `127.0.0.1:443` instead makes it publish the correct `<your-public-ip>:443`,
while still only being reachable via nginx's loopback proxy, never directly from outside.

## A critical thing to know before adding any new transport at all

`nym-bridge` aborts its **entire process** if even one configured listener fails to bind - not
just that one transport. A port conflict on a brand new transport you're adding will take down
the working transports too until you fix it and restart. Always confirm the target port is free
(`ss -ltn "sport = :<port>"` / `ss -lun "sport = :<port>"`) before adding anything, and keep the
pre-change backup (`add-stealth-ports.sh` does both automatically).
