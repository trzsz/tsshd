## tsshd: UDP-based SSH Server with Roaming Support

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/tsshd)](https://github.com/trzsz/tsshd/releases)
[![中文文档](https://img.shields.io/badge/%E4%B8%AD%E6%96%87-%E6%96%87%E6%A1%A3-blue?style=flat)](https://github.com/trzsz/tsshd/blob/main/README.cn.md)

tsshd is a UDP-based SSH server built for unreliable networks. It supports seamless roaming across networks and IP changes, and works well on high-latency links such as cellular connections and unstable Wi-Fi.

tsshd aims to be fully compatible with OpenSSH while providing additional capabilities:

- Survives sleep, wake, and temporary network loss.
- Roams seamlessly across networks and IP changes.
- Supports UDP port forwarding (Local and Remote).

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

3. Use `tssh --udp xxx` to log in. The usage is the same as standard SSH.
   - Latency-sensitive users can specify the `--kcp` option.
   - Alternatively, configure the following in `~/.ssh/config` to omit the `--udp` or `--kcp` option:
     ```
     Host xxx
         #!! UdpMode  ( Yes | QUIC | KCP )
     ```

### How it works

- The `tssh` plays the role of `ssh` on the client side, while the `tsshd` acts as `sshd` on the server side.

- The `tssh` first logs in to the server normally as an ssh client, and then starts a new `tsshd` process on the server, where each session has its own `tsshd` process.

- The `tsshd` process listens on a random UDP port in the range 61001–61999 (configurable via `TsshdPort`), and sends the port number and session secret keys back to the `tssh` process through the SSH channel. The SSH connection is then closed, and `tssh` communicates with `tsshd` over UDP.

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

- Install with Homebrew on MacOS

  <details><summary><code>brew install tsshd</code></summary>

  ```sh
  brew install tsshd
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

### Supported Terminals

The following clients or terminals support the `tsshd` server:

- [trzsz-ssh](https://github.com/trzsz/trzsz-ssh) ( tssh ) – An SSH client designed as a drop-in replacement for the OpenSSH client.

- [rootshell](https://github.com/kitknox/rootshell) - A free, Metal-accelerated terminal emulator for iPhone, iPad, Vision Pro, and Mac.

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

### Security Model

- `Client Proxy` and `KCP/QUIC Client` run in the same process, and `Server Proxy` and `KCP/QUIC Server` run in the same process on the server. The proxy implements the `net.PacketConn` interface, so packets are exchanged **directly in memory** rather than through the local network stack. This prevents other local processes from intercepting or injecting packets.

- `Server Proxy` accepts packets from **only one authenticated client address at a time**. If the client reconnects from a new IP or port (for example after a network change), the new `Client Proxy` must authenticate again. Once authenticated, the new address replaces the previous one and packets from the old address are ignored.

- When a `Client Proxy` connects or reconnects, it sends an **authentication packet** encrypted with **AES-256-GCM**. The encryption key is a session-specific key generated by the server and delivered to the client through the SSH channel during login.

- The `Server Proxy` verifies the client ID and ensures that the authentication sequence number is strictly monotonically increasing across all previously observed authentication packets to prevent replay attacks. Upon successful verification, the server marks the client address as authenticated and responds with an encrypted authentication acknowledgment.

- Communication between the client and server uses encrypted transports provided by [kcp-go](https://github.com/xtaci/kcp-go) or [quic-go](https://github.com/quic-go/quic-go). QUIC uses **TLS 1.3** as the underlying security protocol to ensure confidentiality and integrity of transmitted data, and supports **key updates** throughout the connection lifecycle. For KCP, a custom rekey mechanism is implemented to periodically rotate encryption keys with **forward secrecy**, ensuring that all traffic remains encrypted end-to-end.

### Configurations

```
Host xxx
    #!! UdpMode Yes
    #!! TsshdPort 61001-61999
    #!! TsshdPath ~/go/bin/tsshd
    #!! UdpAliveTimeout 86400
    #!! UdpHeartbeatTimeout 3
    #!! UdpReconnectTimeout 15
    #!! ShowNotificationOnTop yes
    #!! ShowFullNotifications yes
    #!! UdpProxyMode UDP
    #!! UdpMTU 1400
```

- `UdpMode`: `No` (the default: tssh works in TCP mode), `Yes` (default protocol: `QUIC`), `QUIC` ([QUIC](https://github.com/quic-go/quic-go) protocol: faster speed), `KCP` ([KCP](https://github.com/xtaci/kcp-go) protocol: lower latency).

- `TsshdPort`: Specifies the port range that tsshd listens on, default is [61001, 61999]. You can specify multiple discrete ports (e.g., `6022,7022`) or multiple discrete ranges (e.g., `8010-8020,9020-9030,10080`); tsshd will randomly choose an available port. You can also specify the port on the command line using `--tsshd-port`.

- `TsshdPath`: Specifies the path to the tsshd binary on the server, lookup in $PATH if not configured. You can also specify the path on the command line using `--tsshd-path`.

- `UdpAliveTimeout`: If the disconnection lasts longer than `UdpAliveTimeout` in seconds, tssh and tsshd will both exit, and no longer support reconnection. The default is 86400 seconds.

- `UdpHeartbeatTimeout`: If the disconnection lasts longer than `UdpHeartbeatTimeout` in seconds, tssh will try to reconnect to the server by a new path. The default is 3 seconds.

- `UdpReconnectTimeout`: If the disconnection lasts longer than `UdpReconnectTimeout` in seconds, tssh will display a notification indicating that the connection has been lost. The default is 15 seconds.

- `ShowNotificationOnTop`: Whether the connection loss notification is displayed on the top. The default is yes, which may overwrite some of the previous output. Set it to `No` to display notifications on the current line of the cursor.

- `ShowFullNotifications`: Whether to display the full notifications or a brief notification. The default is yes, which may output several lines to the screen. Set it to `No` will output only one line.

- `UdpProxyMode`: The default transport protocol is `UDP`. If `UDP` traffic is blocked by firewalls in your network environment, you can set it to `TCP` to work around the restriction, though this may introduce additional latency.

- `UdpMTU`: Sets the maximum transmission unit (MTU) for UDP packets. Default is 1400.

### Contact

Feel free to email the author <lonnywong@qq.com>, or create an [issue](https://github.com/trzsz/tsshd/issues). Welcome to join the QQ group: 318578930.

### Sponsor

[❤️ Sponsor trzsz ❤️](https://github.com/trzsz), buy the author a drink 🍺 ? Thank you for your support!
