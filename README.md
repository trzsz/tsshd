## tsshd - tssh server that supports connection migration for roaming

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/tsshd)](https://github.com/trzsz/tsshd/releases)
[![中文文档](https://img.shields.io/badge/%E4%B8%AD%E6%96%87-%E6%96%87%E6%A1%A3-blue?style=flat)](https://github.com/trzsz/tsshd/blob/main/README.cn.md)

trzsz-ssh ( tssh ) with tsshd supports intermittent connectivity, allows roaming, and can be used on high-latency links such as cellular data connections, unstable Wi-Fi, etc.

It aims to provide complete compatibility with openssh, mirroring all its features, while also offering additional useful features not found in the openssh client, plus:

- Keeps the session alive if the client goes to sleep and wakes up later, or temporarily loses its connection.

- Allows the client to "roam" and change IP addresses, switching between any networks, while keeping alive.

### Comparison

tsshd was inspired by [mosh](https://github.com/mobile-shell/mosh), and the `tsshd` works like `mosh-server`, while the `tssh --udp` works like `mosh`.

| Feature                   |                     mosh ( mosh-server )                      |              tssh ( tsshd )               |
| ------------------------- | :-----------------------------------------------------------: | :---------------------------------------: |
| Low Latency               |                              ??                               | ✅ [KCP](https://github.com/xtaci/kcp-go) |
| Keep Alive                |                              ✅                               |                    ✅                     |
| Client Roaming            |                              ✅                               |                    ✅                     |
| Local Echo & Line Editing |                              ✅                               |                Not Planned                |
| Multi Platform / Windows  |  [mosh#293](https://github.com/mobile-shell/mosh/issues/293)  |                    ✅                     |
| SSH X11 Forwarding        |   [mosh#41](https://github.com/mobile-shell/mosh/issues/41)   |                    ✅                     |
| SSH Agent Forwarding      |  [mosh#120](https://github.com/mobile-shell/mosh/issues/120)  |                    ✅                     |
| SSH Port Forwarding       |  [mosh#337](https://github.com/mobile-shell/mosh/issues/337)  |                    ✅                     |
| Output Scrollback         |  [mosh#122](https://github.com/mobile-shell/mosh/issues/122)  |                    ✅                     |
| OSC52 Sequence            |  [mosh#637](https://github.com/mobile-shell/mosh/issues/637)  |                    ✅                     |
| ProxyJump                 |  [mosh#970](https://github.com/mobile-shell/mosh/issues/970)  |                    ✅                     |
| tmux -CC Integration      | [mosh#1078](https://github.com/mobile-shell/mosh/issues/1078) |                    ✅                     |

tssh and tsshd works exactly like ssh, there are no plans to support local echo and line editing, and will not have the mosh issues: [mosh#1041](https://github.com/mobile-shell/mosh/issues/1041), [mosh#1281](https://github.com/mobile-shell/mosh/issues/1281), [mosh#1295](https://github.com/mobile-shell/mosh/issues/1295), etc.

### How to use

1. Install [tssh](https://github.com/trzsz/trzsz-ssh?tab=readme-ov-file#installation) on the client ( your local machine ).

2. Install [tsshd](https://github.com/trzsz/tsshd?tab=readme-ov-file#installation) on the server ( the remote host ).

3. Use `tssh --udp xxx` to login to the server. Or configure as follows in `~/.ssh/config` to omit `--udp`:

   ```
   Host xxx
       #!! UdpMode yes
   ```

### How it works

- The `tssh` plays the role of `ssh` on the client side, and the `tsshd` plays the role of `sshd` on the server side.

- The `tssh` will first login to the server normally as an ssh client, and then run a new `tsshd` process on the server.

- The `tsshd` process listens on a random udp port between 61001 and 61999 (can be customized by `UdpPort`), and sends its port number and some secret keys back to the `tssh` process over the ssh channel. The ssh connection is then shut down, and the `tssh` process communicates with the `tsshd` process over udp.

### Reconnection

```
┌───────────────────────┐                ┌───────────────────────┐
│                       │                │                       │
│    tssh (process)     │                │    tsshd (process)    │
│                       │                │                       │
│ ┌───────────────────┐ │                │ ┌───────────────────┐ │
│ │                   │ │                │ │                   │ │
│ │  KCP/QUIC Client  │ │                │ │  KCP/QUIC Server  │ │
│ │                   │ │                │ │                   │ │
│ └───────┬───▲───────┘ │                │ └───────┬───▲───────┘ │
│         │   │         │                │         │   │         │
│         │   │         │                │         │   │         │
│ ┌───────▼───┴───────┐ │                │ ┌───────▼───┴───────┐ │
│ │                   ├─┼────────────────┼─►                   │ │
│ │   Client  Proxy   │ │                │ │   Server  Proxy   │ │
│ │                   ◄─┼────────────────┼─┤                   │ │
│ └───────────────────┘ │                │ └───────────────────┘ │
└───────────────────────┘                └───────────────────────┘
```

- The client `KCP/QUIC Client` and `Client Proxy` are on the same machine and in the same process, and the connection between them will not be interrupted.

- The server `KCP/QUIC Server` and `Server Proxy` are on the same machine and in the same process, and the connection between them will not be interrupted.

- If the client doesn't receive a heartbeat from the server for a period of time, it might be due to network changes causing the original connection to be interrupted. In this case, the `Client Proxy` will re-establish a connection to the `Server Proxy`, and communicate through the new connection after successful authentication. From the perspective of the `KCP/QUIC Client` and the `KCP/QUIC Server`, the connection is never interrupted.

### Security

- The `KCP/QUIC Server` listens only on the localhost at 127.0.0.1, and accepts only one connection. Once the `Server Proxy` in the same process successfully connects, all other connections will be rejected.

- The `Client Proxy` listens only on the localhost at 127.0.0.1, and accepts only one connection. Once the `KCP/QUIC Client` in the same process successfully connects, all other connections will be rejected.

- The `Server Proxy` only forwards packets from the unique and authenticated `Client Proxy`. The `Client Proxy` can change its IP address and port, but once a new `Client Proxy` is authenticated, the `Server Proxy` will only forward packets from the new `Client Proxy`, ignoring the old `Client Proxy` address.

- The `Client Proxy` connects for the first time or reconnects to the `Server Proxy` after changing its IP address and port, it needs to send an authentication message (encrypted using the AES-GCM-256 algorithm, with a one-time key randomly generated by the server, which is sent to the client via the SSH tunnel during login). After the `Server Proxy` successfully decrypts the authentication message (without tampering), it verifies that whether the client ID matches the expectations and whether the sequence number is greater than the sequence number in all previous authentication messages. If so, it marks the client address as an authenticated address and sends an authentication confirmation message (encrypted using the AES-GCM-256 algorithm) to the client. After the `Client Proxy` receives the authentication confirmation message from the `Server Proxy` and decrypts it successfully (without tampering), it verifies the server ID and the sequence number. If they match the expectations, it starts communicating with the `Server Proxy` using the new address, forwarding messages from the local process `KCP/QUIC Client` to the `Server Proxy`. The `Server Proxy` then forwards the messages to the local process `KCP/QUIC Server` service.

- The `KCP/QUIC Client` and the `KCP/QUIC Server` use the open-source [KCP](https://github.com/xtaci/kcp-go) / [QUIC](https://github.com/quic-go/quic-go) protocols, and use encrypted transmission (the key is a one-time key randomly generated by the server, which is sent to the client via the SSH tunnel during login).

### Configurations

```
Host xxx
    #!! UdpMode Yes
    #!! UdpPort 61001-61999
    #!! TsshdPath ~/go/bin/tsshd
    #!! UdpAliveTimeout 86400
    #!! UdpHeartbeatTimeout 3
    #!! UdpReconnectTimeout 15
    #!! ShowNotificationOnTop yes
    #!! ShowFullNotifications yes
```

- `UdpMode`: `No` (the default: tssh works in TCP mode), `Yes` (default protocol: `QUIC`), `QUIC` ([QUIC](https://github.com/quic-go/quic-go) protocol: faster speed), `KCP` ([KCP](https://github.com/xtaci/kcp-go) protocol: lower latency).

- `UdpPort`: Specifies the range of UDP ports that tsshd listens on, the default value is [61001, 61999].

- `TsshdPath`: Specifies the path to the tsshd binary on the server, lookup in $PATH if not configured.

- `UdpAliveTimeout`: If the disconnection lasts longer than `UdpAliveTimeout` in seconds, tssh and tsshd will both exit, and no longer support reconnection. The default is 86400 seconds.

- `UdpHeartbeatTimeout`: If the disconnection lasts longer than `UdpHeartbeatTimeout` in seconds, tssh will try to reconnect to the server by a new path. The default is 3 seconds.

- `UdpReconnectTimeout`: If the disconnection lasts longer than `UdpReconnectTimeout` in seconds, tssh will display a notification indicating that the connection has been lost. The default is 15 seconds.

- `ShowNotificationOnTop`: Whether the connection loss notification is displayed on the top. The default is yes, which may overwrite some of the previous output. Set it to `No` to display notifications on the current line of the cursor.

- `ShowFullNotifications`: Whether to display the full notifications or a brief notification. The default is yes, which may output several lines to the screen. Set it to `No` will output only one line.

### Installation

- Install with apt on Ubuntu

  <details><summary><code>sudo apt install tsshd</code></summary>

  ```sh
  sudo apt update && sudo apt install software-properties-common
  sudo add-apt-repository ppa:trzsz/ppa && sudo apt update

  sudo apt install tsshd
  ```

  </details>

- Install with apt on Debian

  <details><summary><code>sudo apt install tsshd</code></summary>

  ```sh
  sudo apt install curl gpg
  curl -s 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x7074ce75da7cc691c1ae1a7c7e51d1ad956055ca' \
    | gpg --dearmor -o /usr/share/keyrings/trzsz.gpg
  echo 'deb [signed-by=/usr/share/keyrings/trzsz.gpg] https://ppa.launchpadcontent.net/trzsz/ppa/ubuntu jammy main' \
    | sudo tee /etc/apt/sources.list.d/trzsz.list
  sudo apt update

  sudo apt install tsshd
  ```

  </details>

- Install with yum on Linux

  <details><summary><code>sudo yum install tsshd</code></summary>

  - Install with [gemfury](https://gemfury.com/) repository.

    ```sh
    echo '[trzsz]
    name=Trzsz Repo
    baseurl=https://yum.fury.io/trzsz/
    enabled=1
    gpgcheck=0' | sudo tee /etc/yum.repos.d/trzsz.repo

    sudo yum install tsshd
    ```

  - Install with [wlnmp](https://www.wlnmp.com/install) repository. It's not necessary to configure the epel repository for tsshd.

    ```sh
    curl -fsSL "https://sh.wlnmp.com/wlnmp.sh" | bash

    sudo yum install tsshd
    ```

  </details>

- Install with yay on ArchLinux

  <details><summary><code>yay -S tsshd</code></summary>

  ```sh
  yay -Syu
  yay -S tsshd
  ```

  </details>

- Install with scoop on Windows

  <details><summary><code>scoop install tsshd</code></summary>

  ```sh
  scoop bucket add extras
  scoop install tsshd
  ```

  Need to allow `C:\Users\<user>\scoop\apps\tsshd\<version>\tsshd.exe` through the firewall for it to work properly.

  </details>

- Install with Go ( Requires go 1.25 or later )

  <details><summary><code>go install github.com/trzsz/tsshd/cmd/tsshd@latest</code></summary>

  ```sh
  go install github.com/trzsz/tsshd/cmd/tsshd@latest
  ```

  The binaries are usually located in ~/go/bin/ ( C:\Users\your_name\go\bin\ on Windows ).

  </details>

- Build from source ( Requires go 1.25 or later )

  <details><summary><code>sudo make install</code></summary>

  ```sh
  git clone --depth 1 https://github.com/trzsz/tsshd.git
  cd tsshd
  make
  sudo make install
  ```

  </details>

- Download from the [GitHub Releases](https://github.com/trzsz/tsshd/releases) and install locally

  <details><summary><code>download and install locally</code></summary>

  ```sh
  sudo apt install /tmp/tsshd_*.deb

  sudo dpkg -i /tmp/tsshd_*.deb

  sudo dnf install /tmp/tsshd_*.rpm

  sudo yum install /tmp/tsshd_*.rpm

  sudo rpm -i /tmp/tsshd_*.rpm

  tar zxvf tsshd_*.tar.gz && sudo cp tsshd_*/tsshd /usr/bin/
  ```

  </details>

### Contact

Feel free to email the author <lonnywong@qq.com>, or create an [issue](https://github.com/trzsz/tsshd/issues). Welcome to join the QQ group: 318578930.

### Sponsor

[❤️ Sponsor trzsz ❤️](https://github.com/trzsz), buy the author a drink 🍺 ? Thank you for your support!
