# tsshd - 支持连接迁移的 ssh 服务端

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/tsshd)](https://github.com/trzsz/tsshd/releases)

trzsz-ssh ( tssh ) 与 tsshd 一起，适用于高延迟的弱网连接，切换网络、休眠与唤醒都不会掉线，让 ssh 会话永远保持。

tssh 设计为 ssh 客户端的直接替代品，提供与 openssh 完全兼容的基础功能，同时实现其他有用的扩展功能，外加：

- 客户端进入休眠并且迟些再唤醒，或者暂时断开网络，ssh 会话可以保持不掉线。

- 客户端换地方接入，更换 IP 地址，任意切换网络等，ssh 会话可以保持不中断。

## 功能对比

tsshd 的灵感来源于 [mosh](https://github.com/mobile-shell/mosh)，`tsshd` 类似于 `mosh-server`，而 `tssh --udp` 类似于 `mosh`。

| Feature                  |                     mosh ( mosh-server )                      |              tssh ( tsshd )               |
| ------------------------ | :-----------------------------------------------------------: | :---------------------------------------: |
| 超低延迟                 |                              ??                               | ✅ [KCP](https://github.com/xtaci/kcp-go) |
| 保持连接                 |                              ✅                               |                    ✅                     |
| 切换网络                 |                              ✅                               |                    ✅                     |
| 本地回显 & 行编辑        |                              ✅                               |                无支持计划                 |
| 支持多平台 / Windows     |  [mosh#293](https://github.com/mobile-shell/mosh/issues/293)  |                    ✅                     |
| SSH X11 转发             |   [mosh#41](https://github.com/mobile-shell/mosh/issues/41)   |                    ✅                     |
| SSH Agent 转发           |  [mosh#120](https://github.com/mobile-shell/mosh/issues/120)  |                    ✅                     |
| SSH 端口转发             |  [mosh#337](https://github.com/mobile-shell/mosh/issues/337)  |                    ✅                     |
| 输出上下滚动             |  [mosh#122](https://github.com/mobile-shell/mosh/issues/122)  |                    ✅                     |
| OSC52 复制粘贴           |  [mosh#637](https://github.com/mobile-shell/mosh/issues/637)  |                    ✅                     |
| tmux -CC 集成            | [mosh#1078](https://github.com/mobile-shell/mosh/issues/1078) |                    ✅                     |
| ProxyJump / ProxyCommand |  [mosh#970](https://github.com/mobile-shell/mosh/issues/970)  |                 ✅ 第一跳                 |

tssh 和 tsshd 的工作方式与 ssh 完全相同，没有计划支持本地回显和行编辑，也不会出现 mosh 的问题：[mosh#1041](https://github.com/mobile-shell/mosh/issues/1041)、[mosh#1281](https://github.com/mobile-shell/mosh/issues/1281)、[mosh#1295](https://github.com/mobile-shell/mosh/issues/1295) 等。

## 如何使用

1. 在客户端（本地电脑）上安装 [tssh](https://github.com/trzsz/trzsz-ssh)。

2. 在服务端（远程机器）上安装 [tsshd](https://github.com/trzsz/tsshd)。

3. 使用 `tssh --udp` 登录服务器。在 `~/.ssh/config` 中如下配置可省略 `--udp` 参数：

   ```
   Host xxx
       #!! UdpMode yes
   ```

## 原理简介

- `tssh` 在客户端扮演 `ssh` 的角色，`tsshd` 在服务端扮演 `sshd` 的角色。

- `tssh` 会先作为一个 ssh 客户端正常登录到服务器上，然后在服务器上启动一个新的 `tsshd` 进程。

- `tsshd` 进程会随机侦听一个 61001 到 61999 之间的 UDP 端口（可通过 `UdpPort` 配置自定义），并将其端口和密钥通过 ssh 通道发回给 `tssh` 进程。登录的 ssh 连接会被关闭，然后 `tssh` 进程通过 UDP 与 `tsshd` 进程通讯。

## 配置说明

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

- `UdpMode`: `No` (默认为`No`: tssh 工作在 TCP 模式), `Yes` (默认协议: `KCP`), `QUIC` ([QUIC](https://github.com/quic-go/quic-go) 协议), `KCP` ([KCP](https://github.com/xtaci/kcp-go) 协议).

- `UdpPort`: 指定 tsshd 监听的 UDP 端口范围，默认值为 [61001, 61999]。

- `TsshdPath`: 指定服务器上 tsshd 二进制程序的路径，如果未配置，则在 $PATH 中查找。

- `UdpAliveTimeout`: 如果断开连接的时间超过 `UdpAliveTimeout` 秒，tssh 和 tsshd 都会退出，不再支持重连。默认值为 86400 秒。

- `UdpHeartbeatTimeout`: 如果断开连接的时间超过 `UdpHeartbeatTimeout` 秒，tssh 将会尝试换条路重新连到服务器。默认值为 3 秒。

- `UdpReconnectTimeout`: 如果断开连接的时间超过 `UdpReconnectTimeout` 秒，tssh 将会显示失去连接的通知公告。默认值为 15 秒。

- `ShowNotificationOnTop`: 是否在屏幕顶部显示失去连接的通知。默认为 yes，这可能会覆盖之前的一些输出。设置为 `No` 在光标当前行显示通知。

- `ShowFullNotifications`: 是显示完整的通知，还是显示简短的通知。默认为 yes，这可能会输出几行通知到屏幕上。设置为 `No` 只输出一行通知。

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

- 可从 [GitHub Releases](https://github.com/trzsz/tsshd/releases) 中下载，国内可从 [Gitee 发行版](https://gitee.com/trzsz/tsshd/releases) 中下载，解压并加到 `PATH` 环境变量中。

## 联系方式

有什么问题可以发邮件给作者 <lonnywong@qq.com>，也可以提 [Issues](https://github.com/trzsz/tsshd/issues) 。欢迎加入 QQ 群：318578930。

## 赞助打赏

[❤️ 赞助 trzsz ❤️](https://github.com/trzsz)，请作者喝杯咖啡 ☕ ? 谢谢您们的支持！
