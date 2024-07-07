# tsshd

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/tsshd)](https://github.com/trzsz/tsshd/releases)
[![中文文档](https://img.shields.io/badge/%E4%B8%AD%E6%96%87-%E6%96%87%E6%A1%A3-blue?style=flat)](https://github.com/trzsz/tsshd/blob/main/README.cn.md)

The `tsshd` works like `mosh-server`, while the [`tssh --udp`](https://github.com/trzsz/trzsz-ssh) works like [`mosh`](https://github.com/mobile-shell/mosh).

## Advantages

- Low Latency ( based on [QUIC](https://github.com/quic-go/quic-go) / [KCP](https://github.com/xtaci/kcp-go) )

- Port Forwarding ( same as openssh, includes ssh agent forwarding and X11 forwarding )

- _[TODO]_ Connection Migration ( supports network switching and reconnection, depends on [quic-go#234](https://github.com/quic-go/quic-go/issues/234) )

## How to use

1. Install [tssh](https://github.com/trzsz/trzsz-ssh) on the client ( the user's machine ).

2. Install [tsshd](https://github.com/trzsz/tsshd) on the server ( the remote host ).

3. Use `tssh --udp` to login to the server. Configure as follows to omit `--udp`:

   ```
   Host xxx
       #!! UdpMode yes
       #!! TsshdPath ~/go/bin/tsshd
   ```

## How it works

- The `tssh` plays the role of `ssh` on the client side, and the `tsshd` plays the role of `sshd` on the server side.

- The `tssh` will first login to the server normally as an ssh client, and then run a new `tsshd` process on the server.

- The `tsshd` process listens on a random udp port between 61000 and 62000, and sends its port number and a secret key back to the `tssh` process over the ssh channel. The ssh connection is then shut down, and the `tssh` process communicates with the `tsshd` process over udp.

- The `tsshd` supports `QUIC` protocol and `KCP` protocol (the default is `QUIC`), which can be specified on the command line (such as `-oUdpMode=KCP`), or configured as follows:

  ```
  Host xxx
      #!! UdpMode KCP
  ```

## Installation

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

- Install with [yay](https://github.com/Jguer/yay) on ArchLinux

  <details><summary><code>yay -S tsshd</code></summary>

  ```sh
  yay -Syu
  yay -S tsshd
  ```

  </details>

- Install with Go ( Requires go 1.21 or later )

  <details><summary><code>go install github.com/trzsz/tsshd/cmd/tsshd@latest</code></summary>

  ```sh
  go install github.com/trzsz/tsshd/cmd/tsshd@latest
  ```

  The binaries are usually located in ~/go/bin/ ( C:\Users\your_name\go\bin\ on Windows ).

  </details>

- Build from source ( Requires go 1.21 or later )

  <details><summary><code>sudo make install</code></summary>

  ```sh
  git clone --depth 1 https://github.com/trzsz/tsshd.git
  cd tsshd
  make
  sudo make install
  ```

  </details>

- Download from the [GitHub Releases](https://github.com/trzsz/tsshd/releases), unzip and add to `PATH` environment.

## Contact

Feel free to email the author <lonnywong@qq.com>, or create an [issue](https://github.com/trzsz/tsshd/issues). Welcome to join the QQ group: 318578930.

## Sponsor

[❤️ Sponsor trzsz ❤️](https://github.com/trzsz), buy the author a drink 🍺 ? Thank you for your support!
