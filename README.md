## Name
udpcopy - It is an online UDP duplication tool designed for testing purposes.


## Description
It helps identify bugs without deploying your server software to production servers. Additionally, it can be used for smoke testing your products.


## Scenarios
1. **Distributed Stress Testing**  
   Use `udpcopy` to replicate real-world data for stress testing your server software. This helps uncover bugs that may only appear under high-stress conditions.

2. **Hot Backup**  

3. **Online Testing**  
   Verify the stability of your new system and identify bugs that occur in live environments.

4. **Benchmark**  
   Utilize `udpcopy` for performance benchmarking of your server software.


## Usage
### 1. Install

```
a) Download the source code from github:
  git clone https://github.com/wangbin579/udpcopy
b) sh autogen.sh
c) ./configure
d) make
e) make install
```

### 2. Run:

a) On the source host (root privilege is required):

`./udpcopy -x local_port-remote_ip:remote_port`
 
b) On the target host 

```
iptables -I OUTPUT -p udp --sport port -j QUEUE # if not set
```

## Note
1. **Tested on Linux Only**  
   The tool is tested exclusively on Linux (kernel 2.6 or above).

2. **Packet Loss**  
   `udpcopy` may experience packet loss, which can result in lost requests.

3. **Single-Threaded**  
   Currently, `udpcopy` operates in a single-threaded mode.

4. **Root Privilege Required**  
   Root privileges are necessary for running `udpcopy`.

## Bugs and Feature Requests
Have a bug or a feature request? [Please open a new issue](https://github.com/wangbin579/udpcopy/issues). Before opening any issue, please search for existing issues.

## Copyright and License
Copyright 2024 under [the BSD license](LICENSE).
