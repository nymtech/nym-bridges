

## UDP Sender

```sh
udp-sender -b "[::1]:0" "[::1]:8080" -s 3333 --vv
```

## UDP Receiver

```sh
udp-recv -b "[::1]:50001" -s 3333 --vv
```

## Simple Client UDP 

```sh
client-udp -c ../test-env/test-config/local/client_quic.toml
```