# tsshd

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/tsshd)](https://github.com/trzsz/tsshd/releases)

`tsshd` 类似于 `mosh-server`，而 [`tssh --udp`](https://github.com/trzsz/trzsz-ssh) 类似于 [`mosh`](https://github.com/mobile-shell/mosh)。

## 优点简介

- 降低延迟（ 基于 [QUIC](https://github.com/quic-go/quic-go) / [KCP](https://github.com/xtaci/kcp-go) ）

- 端口转发（ 与 openssh 相同，包括 ssh agent 转发和 X11 转发 ）

- 连接迁移（ 支持 tssh 客户端休眠与唤醒、网络切换、断线重连等 ）

- 代理跳转 ( 第一跳支持 UDP：`客户端 ---udp--> 跳板机 ---tcp--> 服务器` )

## 如何使用

1. 在客户端（本地电脑）上安装 [tssh](https://github.com/trzsz/trzsz-ssh)。

2. 在服务端（远程机器）上安装 [tsshd](https://github.com/trzsz/tsshd)。

3. 使用 `tssh --udp` 登录服务器。如下配置可省略 `--udp` 参数：

   ```
   Host xxx
       #!! UdpMode yes
       #!! TsshdPath ~/go/bin/tsshd
   ```

## 原理简介

- `tssh` 在客户端扮演 `ssh` 的角色，`tsshd` 在服务端扮演 `sshd` 的角色。

- `tssh` 会先作为一个 ssh 客户端正常登录到服务器上，然后在服务器上启动一个新的 `tsshd` 进程。

- `tsshd` 进程会随机侦听一个 61000 到 62000 之间的 UDP 端口，并将其端口和密钥通过 ssh 通道发回给 `tssh` 进程。登录的 ssh 连接会被关闭，然后 `tssh` 进程通过 UDP 与 `tsshd` 进程通讯。

- `tsshd` 支持 `QUIC` 协议和 `KCP` 协议（默认是 `QUIC` 协议），可以命令行指定（如 `-oUdpMode=KCP`），或如下配置：

  ```
  Host xxx
      #!! UdpMode KCP
  ```

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

- ArchLinux 可用 [yay](https://github.com/Jguer/yay) 安装

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
