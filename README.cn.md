# tsshd: 基于 UDP 支持漫游的 SSH 服务器

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/tsshd)](https://github.com/trzsz/tsshd/releases)

tsshd 是一个基于 UDP 的 SSH 服务器，专为不稳定网络环境设计，支持在网络切换或 IP 变化时无缝漫游，并能在高延迟链路（如蜂窝网络和不稳定的 Wi-Fi）上稳定工作。

tsshd 旨在与 OpenSSH 完全兼容，并提供额外能力：

- 客户端休眠、唤醒或临时网络中断时，SSH 会话仍可保持。
- 在网络切换或 IP 变化时无缝漫游，不会中断 SSH 会话。
- 支持 UDP 端口转发 ( LocalForward 和 RemoteForward )。

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

3. 使用 `tssh --udp xxx` 登录服务器，用法与标准 SSH 保持一致。
   - 对延迟敏感的用户可以指定 `--kcp` 选项。
   - 可在 `~/.ssh/config` 中进行如下配置，以省略手动指定 `--udp` 或 `--kcp` 选项：
     ```
     Host xxx
         #!! UdpMode  ( Yes | QUIC | KCP )
     ```

## 原理简介

- `tssh` 在客户端扮演 `ssh` 的角色，`tsshd` 在服务端扮演 `sshd` 的角色。

- `tssh` 会先作为一个 ssh 客户端正常登录到服务器上，然后在服务器上启动一个 `tsshd` 进程（每次登录都是一个独立的 `tsshd` 进程）。

- `tsshd` 进程会随机侦听一个 61001 到 61999 之间的 UDP 端口（可通过 `TsshdPort` 配置自定义），并将其端口和几个密钥通过 ssh 通道发回给 `tssh` 进程。登录的 ssh 连接会被关闭，然后 `tssh` 进程通过 UDP 与 `tsshd` 进程通讯。

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

- MacOS 可用 Homebrew 安装

  <details><summary><code>brew install tsshd</code></summary>

  ```sh
  brew install tsshd
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

## 支持终端

以下客户端或终端支持 `tsshd` 服务端：

- [trzsz-ssh](https://github.com/trzsz/trzsz-ssh) ( tssh ) – 一款用 Go 实现，可直接替代 OpenSSH 客户端的 SSH 客户端。

- [rootshell](https://github.com/kitknox/rootshell) - 一款支持 iPhone、iPad、Vision Pro 和 Mac 平台的免费终端模拟器。

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

## 安全模型

- `Client Proxy` 与 `KCP/QUIC Client` 运行在客户端同一进程内，`Server Proxy` 与 `KCP/QUIC Server` 也运行在服务器的同一进程内，两个 `Proxy` 均实现了 `net.PacketConn` 接口，数据在内存中直接传递，不经过本地网络协议栈，从而降低被本地其他进程窃听或注入的风险。

- `Server Proxy` 只接受来自认证过的客户端地址的报文。如果客户端因网络变化从新的 IP 或端口重新连接，必须重新完成认证。认证成功后，新地址将替换旧地址，来自旧地址的报文将被忽略。

- `Client Proxy` 在首次连接或重新连接时，需要发送使用 **AES-256-GCM** 加密的认证报文。认证密钥由服务器在 SSH 登录阶段生成，并通过 SSH 安全通道传输给客户端。

- `Server Proxy` 校验客户端 ID，并确保认证序列号严格单调递增，即新序列号必须大于系统历史上所有已接收的认证序列号，以防止重放攻击。验证通过后，服务器将客户端地址标记为已认证，并返回加密的认证确认报文。

- 客户端与服务器之间使用 [kcp-go](https://github.com/xtaci/kcp-go) 或 [quic-go](https://github.com/quic-go/quic-go) 进行端到端加密通信。QUIC 使用 **TLS 1.3** 作为安全协议基础，确保通信数据的机密性和完整性，并支持连接生命周期内的密钥更新机制。KCP 实现自定义密钥轮换机制，周期性更新加密密钥以提供前向安全性，确保通信始终保持端到端加密。

## 配置说明

### Server 配置 (tsshd)

- 默认情况下，tsshd 会复用 OpenSSH 的配置（默认路径 `/etc/ssh/sshd_config`），以尽可能保持与 OpenSSH 一致的行为。

- 如果存在 `$XDG_CONFIG_HOME/tsshd/sshd_config`（默认 `~/.config/tsshd/sshd_config`），tsshd 会优先使用它（即使文件为空）。

### Client 配置 (tssh)

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

- `UdpMode`: `No` (默认为`No`: tssh 工作在 TCP 模式), `Yes` (默认协议: `QUIC`), `QUIC` ([QUIC](https://github.com/quic-go/quic-go) 协议：速度更快), `KCP` ([KCP](https://github.com/xtaci/kcp-go) 协议：延迟更低).

- `TsshdPort`: 指定 tsshd 监听的端口范围，默认值为 [61001, 61999]。支持指定离散的端口列表(如`6022,7022`)，也支持指定离散的端口范围(如`8010-8020,9020-9030,10080`)，tsshd 会随机监听其中一个空闲的端口。也可在命令行中使用 `--tsshd-port` 指定端口。

- `TsshdPath`: 指定服务器上 tsshd 二进制程序的路径，如果未配置，则在 $PATH 中查找。也可在命令行中使用 `--tsshd-path` 指定路径。

- `UdpAliveTimeout`: 如果断开连接的时间超过 `UdpAliveTimeout` 秒，tssh 和 tsshd 都会退出，不再支持重连。默认值为 86400 秒。

- `UdpHeartbeatTimeout`: 如果断开连接的时间超过 `UdpHeartbeatTimeout` 秒，tssh 将会尝试换条路重新连到服务器。默认值为 3 秒。

- `UdpReconnectTimeout`: 如果断开连接的时间超过 `UdpReconnectTimeout` 秒，tssh 将会显示失去连接的通知公告。默认值为 15 秒。

- `ShowNotificationOnTop`: 是否在屏幕顶部显示失去连接的通知。默认为 yes，这可能会覆盖之前的一些输出。设置为 `No` 在光标当前行显示通知。

- `ShowFullNotifications`: 是显示完整的通知，还是显示简短的通知。默认为 yes，这可能会输出几行通知到屏幕上。设置为 `No` 只输出一行通知。

- `UdpProxyMode`: 默认使用 `UDP` 协议进行传输。如果所在的网络环境有防火墙禁止了 `UDP` 流量，可以配置为 `TCP` 以绕过防火墙限制，但这可能会带来额外的延迟。

- `UdpMTU`: 设置 UDP 数据包的最大传输单元（MTU），默认值为 1400。

## 联系方式

有什么问题可以发邮件给作者 <lonnywong@qq.com>，也可以提 [Issues](https://github.com/trzsz/tsshd/issues) 。欢迎加入 QQ 群：318578930。

## 赞助打赏

[❤️ 赞助 trzsz ❤️](https://github.com/trzsz)，请作者喝杯咖啡 ☕ ? 谢谢您们的支持！
