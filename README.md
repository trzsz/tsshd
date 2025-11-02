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
| tmux -CC Integration      | [mosh#1078](https://github.com/mobile-shell/mosh/issues/1078) |                    ✅                     |
| ProxyJump / ProxyCommand  |  [mosh#970](https://github.com/mobile-shell/mosh/issues/970)  |               ✅ First Hop                |

tssh and tsshd works exactly like ssh, there are no plans to support local echo and line editing, and will not have the mosh issues: [mosh#1041](https://github.com/mobile-shell/mosh/issues/1041), [mosh#1281](https://github.com/mobile-shell/mosh/issues/1281), [mosh#1295](https://github.com/mobile-shell/mosh/issues/1295), etc.

### How to use

1. Install [tssh](https://github.com/trzsz/trzsz-ssh) on the client ( the user's machine ).

2. Install [tsshd](https://github.com/trzsz/tsshd) on the server ( the remote host ).

3. Use `tssh --udp` to login to the server. Or configure as follows in `~/.ssh/config` to omit `--udp`:

   ```
   Host xxx
       #!! UdpMode yes
   ```

### How it works

- The `tssh` plays the role of `ssh` on the client side, and the `tsshd` plays the role of `sshd` on the server side.

- The `tssh` will first login to the server normally as an ssh client, and then run a new `tsshd` process on the server.

- The `tsshd` process listens on a random udp port between 61001 and 61999 (can be customized by `UdpPort`), and sends its port number and a secret key back to the `tssh` process over the ssh channel. The ssh connection is then shut down, and the `tssh` process communicates with the `tsshd` process over udp.

### Configurations

```
Host xxx
    #!! UdpMode KCP
    #!! UdpPort 61001-61999
    #!! TsshdPath ~/go/bin/tsshd
    #!! UdpAliveTimeout 86400
    #!! UdpHeartbeatTimeout 3
    #!! UdpReconnectTimeout 15
    #!! ShowNotificationOnTop yes
    #!! ShowFullNotifications yes
```

- `UdpMode`: `No` (the default: tssh works in TCP mode), `Yes` (default protocol: `KCP`), `QUIC` ([QUIC](https://github.com/quic-go/quic-go) protocol), `KCP` ([KCP](https://github.com/xtaci/kcp-go) protocol).

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

- Download from the [GitHub Releases](https://github.com/trzsz/tsshd/releases), unzip and add to `PATH` environment.

### Contact

Feel free to email the author <lonnywong@qq.com>, or create an [issue](https://github.com/trzsz/tsshd/issues). Welcome to join the QQ group: 318578930.

### Sponsor

[❤️ Sponsor trzsz ❤️](https://github.com/trzsz), buy the author a drink 🍺 ? Thank you for your support!
