# pinger

A simple tool for sending ICMP Echo Request packets to a given target

## Build it

```
cargo build
```

## Run it

`pingers` takes a single argument which is a CSV-formatted table of target
parameters. Each target row consists of:

* the target ipv4 address
* the number of pings to send
* the interval between pings

Target parameters must be separated by commas. Target rows must be separated by
semi-colons.

```
$ echo '1.1.1.1,10,100;8.8.8.8,3,1000' | xargs ./target/debug/pingers
8.8.8.8,0,20441
1.1.1.1,0,20468
1.1.1.1,1,20390
1.1.1.1,2,19251
1.1.1.1,3,18446
1.1.1.1,4,19516
1.1.1.1,5,19237
1.1.1.1,6,20416
1.1.1.1,7,20688
1.1.1.1,8,26462
1.1.1.1,9,21315
8.8.8.8,1,19637
8.8.8.8,2,19267
```

**Note**: this either needs to be run as root OR the binary needs to be given
enhanced network-related capabilities, eg:

```
# setcap cap_net_admin,cap_net_raw+ep ./target/debug/pingers
```
