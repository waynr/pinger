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
$ echo '1.1.1.1,30,100;8.8.8.8,3,1000' | xargs ./target/debug/pingers
8.8.8.8,0,18
1.1.1.1,0,18
1.1.1.1,1,21
1.1.1.1,2,19
1.1.1.1,3,20
1.1.1.1,4,20
1.1.1.1,5,20
1.1.1.1,6,19
1.1.1.1,7,19
1.1.1.1,8,20
1.1.1.1,9,17
8.8.8.8,1,0
1.1.1.1,10,18
1.1.1.1,11,19
1.1.1.1,12,20
1.1.1.1,13,21
1.1.1.1,14,TIMEDOUT
1.1.1.1,15,21
1.1.1.1,16,20
1.1.1.1,17,19
1.1.1.1,18,20
1.1.1.1,19,18
8.8.8.8,2,0
1.1.1.1,20,21
1.1.1.1,21,19
1.1.1.1,22,19
1.1.1.1,23,18
1.1.1.1,24,20
1.1.1.1,25,19
1.1.1.1,26,20
1.1.1.1,27,TIMEDOUT
1.1.1.1,28,19
1.1.1.1,29,21
```
