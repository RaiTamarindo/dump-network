# Dump network cli

## Dependencies

-   LIBPCAP:

```sh
apt install -y libpcap-dev
```

## How to run

-   Build the binary

```sh
make build
```

-   Run with privileges

```sh
sudo ./bin/netdump watch eth0 --port=123 --udp
```
