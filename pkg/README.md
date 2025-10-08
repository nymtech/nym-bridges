
# Packaging


### Debian

Build debian package for the `nym-bridge` as a service.

```sh
# from repository root
cargo deb
```


Check build artifacts

```sh
# check simple debian best practices 
lintian target/debian/nym-bridge_0.1.0-1_amd64.de

# look at files included in package
mkdir debdir
dpkg-deb -R target/debian/nym-bridge_0.1.0-1_amd64.deb debdir
tree debdir
```
