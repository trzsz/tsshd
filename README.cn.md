# tsshd - 支持连接迁移的 ssh 服务端

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/tsshd)](https://github.com/trzsz/tsshd/releases)

trzsz-ssh ( tssh ) 与 tsshd 一起，适用于高延迟的弱网连接，切换网络、休眠与唤醒都不会掉线，让 ssh 会话永远保持。

tssh 设计为 ssh 客户端的直接替代品，提供与 openssh 完全兼容的基础功能，同时实现其他有用的扩展功能，外加：

- 客户端进入休眠并且迟些再唤醒，或者暂时断开网络，ssh 会话可以保持不掉线。

- 客户端换地方接入，更换 IP 地址，任意切换网络等，ssh 会话可以保持不中断。

## 功能对比

tsshd 的灵感来源于 [mosh](https://github.com/mobile-shell/mosh)，`tsshd` 类似于 `mosh-server`，而 `tssh --udp` 类似于 `mosh`。

| Feature              |                     mosh ( mosh-server )                      |              tssh ( tsshd )               |
| -------------------- | :-----------------------------------------------------------: | :---------------------------------------: |
| 超低延迟             |                              ??                               | ✅ [KCP](https://github.com/xtaci/kcp-go) |
| 保持连接             |                              ✅                               |                    ✅                     |
| 切换网络             |                              ✅                               |                    ✅                     |
| 本地回显 & 行编辑    |                              ✅                               |                无支持计划                 |
| 支持多平台 / Windows |  [mosh#293](https://github.com/mobile-shell/mosh/issues/293)  |                    ✅                     |
| SSH X11 转发         |   [mosh#41](https://github.com/mobile-shell/mosh/issues/41)   |                    ✅                     |
| SSH Agent 转发       |  [mosh#120](https://github.com/mobile-shell/mosh/issues/120)  |                    ✅                     |
| SSH 端口转发         |  [mosh#337](https://github.com/mobile-shell/mosh/issues/337)  |                    ✅                     |
| 输出上下滚动         |  [mosh#122](https://github.com/mobile-shell/mosh/issues/122)  |                    ✅                     |
| OSC52 复制粘贴       |  [mosh#637](https://github.com/mobile-shell/mosh/issues/637)  |                    ✅                     |
| ProxyJump            |  [mosh#970](https://github.com/mobile-shell/mosh/issues/970)  |                    ✅                     |
| tmux -CC 集成        | [mosh#1078](https://github.com/mobile-shell/mosh/issues/1078) |                    ✅                     |

tssh 和 tsshd 的工作方式与 ssh 完全相同，没有计划支持本地回显和行编辑，也不会出现 mosh 的问题：[mosh#1041](https://github.com/mobile-shell/mosh/issues/1041)、[mosh#1281](https://github.com/mobile-shell/mosh/issues/1281)、[mosh#1295](https://github.com/mobile-shell/mosh/issues/1295) 等。

## 如何使用

1. 在客户端（本地电脑）上安装 [tssh](https://github.com/trzsz/trzsz-ssh?tab=readme-ov-file#installation)。

2. 在服务端（远程机器）上安装 [tsshd](https://github.com/trzsz/tsshd?tab=readme-ov-file#installation)。

3. 使用 `tssh --udp xxx` 登录服务器。在 `~/.ssh/config` 中如下配置可省略 `--udp` 参数：

   ```
   Host xxx
       #!! UdpMode yes
   ```

## 原理简介

- `tssh` 在客户端扮演 `ssh` 的角色，`tsshd` 在服务端扮演 `sshd` 的角色。

- `tssh` 会先作为一个 ssh 客户端正常登录到服务器上，然后在服务器上启动一个新的 `tsshd` 进程。

- `tsshd` 进程会随机侦听一个 61001 到 61999 之间的 UDP 端口（可通过 `UdpPort` 配置自定义），并将其端口和几个密钥通过 ssh 通道发回给 `tssh` 进程。登录的 ssh 连接会被关闭，然后 `tssh` 进程通过 UDP 与 `tsshd` 进程通讯。

## 重连架构

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

- 客户端 `KCP/QUIC Client` 和 `Client Proxy` 在同一台机同一个进程内，它们之间的连接不会断。

- 服务端 `KCP/QUIC Server` 和 `Server Proxy` 在同一台机同一个进程内，它们之间的连接不会断。

- 客户端较长时间没收到服务端的心跳包时，可能是因为网络变化导致原连接失效了，则由 `Client Proxy` 重新建一个到 `Server Proxy` 的连接，认证通过后就使用新连接进行通讯。在 `KCP/QUIC Client` 和 `KCP/QUIC Server` 看来，连接从来没有断开过。

## 安全保障

- 服务端 `KCP/QUIC Server` 只监听本机 127.0.0.1，并且只接受一个连接，在本进程的 `Server Proxy` 连上后，其他所有连接都会直接拒绝。

- 客户端 `Client Proxy` 只监听本机 127.0.0.1，并且只接受一个连接，在本进程的 `KCP/QUIC Client` 连上后，其他所有连接都会直接拒绝。

- 服务端 `Server Proxy` 只转发认证过的唯一的客户端 `Client Proxy` 的报文。客户端 `Client Proxy` 可以换 IP 地址和端口，但新的客户端 `Client Proxy` 认证后，服务端 `Server Proxy` 就只为新的客户端 `Client Proxy` 转发报文，忽略旧的客户端 `Client Proxy` 地址。

- 客户端 `Client Proxy` 首次连接或换新 IP 端口重新连接到服务端 `Server Proxy` 时，需要先发送认证报文（ 使用 AES-GCM-256 算法加密，密钥是服务端随机生成的一次性密钥，登录时通过 ssh 通道发送给客户端 ）。服务端 `Server Proxy` 正常解密认证报文（未被篡改）后，校验客户端 ID 符合预期，校验序列号比之前收到过的所有认证报文中的序列号都要大，则将该客户端地址标为已认证地址，同时向客户端发送认证确认报文（ 使用 AES-GCM-256 算法加密 ）。客户端 `Client Proxy` 收到服务端 `Server Proxy` 的认证确认报文并正常解密（未被篡改）后，校验服务端 ID 和序列号，符合预期则开始使用新地址与服务端 `Server Proxy` 通讯，将来自本进程 `KCP/QUIC Client` 的报文转发给服务端 `Server Proxy`，服务端 `Server Proxy` 再转发给本进程的 `KCP/QUIC Server` 服务。

- 客户端 `KCP/QUIC Client` 与服务端 `KCP/QUIC Server` 使用开源的 [KCP](https://github.com/xtaci/kcp-go) / [QUIC](https://github.com/quic-go/quic-go) 协议，全程使用加密传输（ 密钥是服务端随机生成的一次性密钥，登录时通过 ssh 通道发送给客户端 ）。

## 配置说明

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
    #!! UdpProxyMode UDP
```

- `UdpMode`: `No` (默认为`No`: tssh 工作在 TCP 模式), `Yes` (默认协议: `QUIC`), `QUIC` ([QUIC](https://github.com/quic-go/quic-go) 协议：速度更快), `KCP` ([KCP](https://github.com/xtaci/kcp-go) 协议：延迟更低).

- `UdpPort`: 指定 tsshd 监听的 UDP 端口范围，默认值为 [61001, 61999]。

- `TsshdPath`: 指定服务器上 tsshd 二进制程序的路径，如果未配置，则在 $PATH 中查找。

- `UdpAliveTimeout`: 如果断开连接的时间超过 `UdpAliveTimeout` 秒，tssh 和 tsshd 都会退出，不再支持重连。默认值为 86400 秒。

- `UdpHeartbeatTimeout`: 如果断开连接的时间超过 `UdpHeartbeatTimeout` 秒，tssh 将会尝试换条路重新连到服务器。默认值为 3 秒。

- `UdpReconnectTimeout`: 如果断开连接的时间超过 `UdpReconnectTimeout` 秒，tssh 将会显示失去连接的通知公告。默认值为 15 秒。

- `ShowNotificationOnTop`: 是否在屏幕顶部显示失去连接的通知。默认为 yes，这可能会覆盖之前的一些输出。设置为 `No` 在光标当前行显示通知。

- `ShowFullNotifications`: 是显示完整的通知，还是显示简短的通知。默认为 yes，这可能会输出几行通知到屏幕上。设置为 `No` 只输出一行通知。

- `UdpProxyMode`: 默认使用 `UDP` 协议进行传输。如果所在的网络环境有防火墙禁止了 `UDP` 流量，可以配置为 `TCP` 以绕过防火墙限制，但这可能会带来额外的延迟。

## 安装方法

- Ubuntu 可用 apt 安装

  <details><summary><code>sudo apt install tsshd</code></summary>

  ```sh
  sudo apt update && sudo apt install software-properties-common
  sudo add-apt-repository ppa:trzsz/ppa && sudo apt update

  sudo apt install tsshd
  ```

  </details>

- Debian 可用 apt 安装

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

- Linux 可用 yum 安装

  <details><summary><code>sudo yum install tsshd</code></summary>

  - 国内推荐使用 [wlnmp](https://www.wlnmp.com/install) 源，安装 tsshd 只需要添加 wlnmp 源（ 配置 epel 源不是必须的 ）：

    ```sh
    curl -fsSL "https://sh.wlnmp.com/wlnmp.sh" | bash

    sudo yum install tsshd
    ```

  - 也可使用 [gemfury](https://gemfury.com/) 源（ 只要网络通，所有操作系统通用 ）

    ```sh
    echo '[trzsz]
    name=Trzsz Repo
    baseurl=https://yum.fury.io/trzsz/
    enabled=1
    gpgcheck=0' | sudo tee /etc/yum.repos.d/trzsz.repo

    sudo yum install tsshd
    ```

  </details>

- ArchLinux 可用 yay 安装

  <details><summary><code>yay -S tsshd</code></summary>

  ```sh
  yay -Syu
  yay -S tsshd
  ```

  </details>

- Windows 可用 scoop 安装

  <details><summary><code>scoop install tsshd</code></summary>

  ```sh
  scoop bucket add extras
  scoop install tsshd
  ```

  需要允许 `C:\Users\<user>\scoop\apps\tsshd\<version>\tsshd.exe` 通过防火墙，才能正常使用。

  </details>

- 用 Go 直接安装（ 要求 go 1.25 以上 ）

  <details><summary><code>go install github.com/trzsz/tsshd/cmd/tsshd@latest</code></summary>

  ```sh
  go install github.com/trzsz/tsshd/cmd/tsshd@latest
  ```

  安装后，`tsshd` 程序一般位于 `~/go/bin/` 目录下（ Windows 一般在 `C:\Users\your_name\go\bin\` ）。

  </details>

- 用 Go 自己编译（ 要求 go 1.25 以上 ）

  <details><summary><code>sudo make install</code></summary>

  ```sh
  git clone --depth 1 https://github.com/trzsz/tsshd.git
  cd tsshd
  make
  sudo make install
  ```

  </details>

- 可从 [GitHub Releases](https://github.com/trzsz/tsshd/releases) 中下载，国内可从 [Gitee 发行版](https://gitee.com/trzsz/tsshd/releases) 中下载，然后本地安装。

  <details><summary><code>下载并本地安装</code></summary>

  ```sh
  sudo apt install /tmp/tsshd_*.deb

  sudo dpkg -i /tmp/tsshd_*.deb

  sudo dnf install /tmp/tsshd_*.rpm

  sudo yum install /tmp/tsshd_*.rpm

  sudo rpm -i /tmp/tsshd_*.rpm

  tar zxvf tsshd_*.tar.gz && sudo cp tsshd_*/tsshd /usr/bin/
  ```

  </details>

## 联系方式

有什么问题可以发邮件给作者 <lonnywong@qq.com>，也可以提 [Issues](https://github.com/trzsz/tsshd/issues) 。欢迎加入 QQ 群：318578930。

## 赞助打赏

[❤️ 赞助 trzsz ❤️](https://github.com/trzsz)，请作者喝杯咖啡 ☕ ? 谢谢您们的支持！
