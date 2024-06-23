# tsshd

The [`tssh --udp`](https://github.com/trzsz/trzsz-ssh) works like [`mosh`](https://github.com/mobile-shell/mosh), and the `tsshd` works like `mosh-server`.

## Advanced Features

- Low latency ( based on kcp )

- Port forwarding ( same as ssh )

## How to use

1. Install [tssh](https://github.com/trzsz/trzsz-ssh) on the client ( the user's machine ).

2. Install [tsshd](https://github.com/trzsz/tsshd) on the server ( the remote host ).

3. Use `tssh --udp xxx` to login to the server. Configure as follows to omit `--udp`:

   ```
   Host xxx
       #!! UdpMode yes
       #!! TsshdPath ~/go/bin/tsshd
   ```

## How it works

The `tssh` plays the role of `ssh` on the client side, and the `tsshd` plays the role of `sshd` on the server side.

The `tssh` will first login to the server normally as an ssh client, and then run a new `tsshd` process on the server.

The `tsshd` process listens on a random udp port between 61000 and 62000, and sends its port number and a secret key back to the `tssh` process over the ssh channel. The ssh connection is then shut down, and the `tssh` process communicates with the `tsshd` process over udp.

## Installation

- Install with Go ( Requires go 1.20 or later )

  <details><summary><code>go install github.com/trzsz/tsshd/cmd/tsshd@latest</code></summary>

  ```sh
  go install github.com/trzsz/tsshd/cmd/tsshd@latest
  ```

  The binaries are usually located in ~/go/bin/ ( C:\Users\your_name\go\bin\ on Windows ).

  </details>

- Build from source ( Requires go 1.20 or later )

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
