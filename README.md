## tsshd: UDP-based SSH Server with Seamless Roaming and Auto-Reconnect

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/tsshd)](https://github.com/trzsz/tsshd/releases)
[![WebSite](https://img.shields.io/badge/WebSite-https%3A%2F%2Ftrzsz.github.io%2Ftsshd-blue?style=flat)](https://trzsz.github.io/tsshd)
[![中文文档](https://img.shields.io/badge/%E4%B8%AD%E6%96%87%E6%96%87%E6%A1%A3-https%3A%2F%2Ftrzsz.github.io%2Fcn%2Ftsshd-blue?style=flat)](https://trzsz.github.io/cn/tsshd)

**tsshd** is a UDP-based SSH server built for unreliable networks. It supports seamless roaming across networks and IP changes, and works well on high-latency links such as cellular connections and unstable Wi-Fi.

**tsshd** aims to be fully compatible with OpenSSH while providing additional capabilities:

- Survives sleep, wake, and temporary network loss.
- Roams seamlessly across networks and IP changes.
- Supports UDP port forwarding (Local and Remote).

### Comparison

**tsshd** was inspired by [mosh](https://github.com/mobile-shell/mosh), and the `tsshd` works like `mosh-server`, while the `tssh --udp` works like `mosh`.

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
         #!! UdpMode  ( yes | QUIC | KCP )
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

- Install with dnf on Fedora / CentOS / RHEL

  <details><summary><code>sudo dnf install tsshd</code></summary>

  ```sh
  sudo dnf copr enable @trzsz/trzsz
  sudo dnf install tsshd
  ```

  </details>

- Install with yum on Legacy CentOS / RHEL

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

- Install with pixi / conda / mamba from [conda-forge](https://github.com/conda-forge/tsshd-feedstock)

  <details><summary><code>pixi global install tsshd</code> / <code>conda install tsshd</code> / <code>mamba install tsshd</code></summary>

  ```sh
  pixi global install tsshd
  ```

  ```sh
  conda install -c conda-forge tsshd
  ```

  ```sh
  mamba install -c conda-forge tsshd
  ```

  </details>

- Install with Go ( Requires go 1.25 or later )

  <details><summary><code>go install github.com/trzsz/tsshd/cmd/tsshd@latest</code></summary>

  ```sh
  # latest release
  go install github.com/trzsz/tsshd/cmd/tsshd@latest

  # latest development version (main branch)
  go install github.com/trzsz/tsshd/cmd/tsshd@main
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

- Download from the [GitHub Releases](https://github.com/trzsz/tsshd/releases) (or [Pre-Release](https://github.com/trzsz/tsshd/releases/tag/dev)) and install locally

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

#### Server Configuration (tsshd)

- By default, tsshd reuses OpenSSH configuration (default `/etc/ssh/sshd_config` on Unix-like systems), ensuring behavior is consistent with OpenSSH.

- If `$XDG_CONFIG_HOME/tsshd/sshd_config` exists (default `~/.config/tsshd/sshd_config`), tsshd prefers it over the OpenSSH config, even if it is empty.

#### Client Configuration (tssh)

```
Host xxx
    #!! UdpMode yes
    #!! TsshdPort 61001-61999
    #!! TsshdPath ~/go/bin/tsshd
    #!! UdpAliveTimeout 86400
    #!! UdpHeartbeatTimeout 3
    #!! UdpReconnectTimeout 15
    #!! ShowNotificationOnTop yes
    #!! ShowFullNotifications yes
    #!! UdpProxyMode UDP
    #!! UdpMTU 1400
    #!! UdpSessionAttach no
    #!! UdpSessionName xxx
```

- `UdpMode`: `no` (the default: tssh works in TCP mode), `yes` (default protocol: `QUIC`), `QUIC` ([QUIC](https://github.com/quic-go/quic-go) protocol: faster speed), `KCP` ([KCP](https://github.com/xtaci/kcp-go) protocol: lower latency).

- `TsshdPort`: Specifies the port range that tsshd listens on, default is [61001, 61999]. You can specify multiple discrete ports (e.g., `6022,7022`) or multiple discrete ranges (e.g., `8010-8020,9020-9030,10080`); tsshd will randomly choose an available port. You can also specify the port on the command line using `--tsshd-port`.

- `TsshdPath`: Specifies the path to the tsshd binary on the server, lookup in $PATH if not configured. You can also specify the path on the command line using `--tsshd-path`.

- `UdpAliveTimeout`: If the disconnection lasts longer than `UdpAliveTimeout` in seconds, tssh and tsshd will both exit, and no longer support reconnection. The default is 86400 seconds.

- `UdpHeartbeatTimeout`: If the disconnection lasts longer than `UdpHeartbeatTimeout` in seconds, tssh will try to reconnect to the server by a new path. The default is 3 seconds.

- `UdpReconnectTimeout`: If the disconnection lasts longer than `UdpReconnectTimeout` in seconds, tssh will display a notification indicating that the connection has been lost. The default is 15 seconds.

- `ShowNotificationOnTop`: Whether the connection loss notification is displayed on the top. The default is yes, which may overwrite some of the previous output. Set it to `no` to display notifications on the current line of the cursor.

- `ShowFullNotifications`: Whether to display the full notifications or a brief notification. The default is yes, which may output several lines to the screen. Set it to `no` will output only one line.

- `UdpProxyMode`: The default transport protocol is `UDP`. If `UDP` traffic is blocked by firewalls in your network environment, you can set it to `TCP` to work around the restriction, though this may introduce additional latency.

- `UdpMTU`: Sets the maximum transmission unit (MTU) for UDP packets. Default is 1400.

- `UdpSessionAttach`: Defaults to `no`. When set to `yes`, it allows attaching to an existing session on the server. Meanwhile, the current session will also be made attachable, allowing you to re-attach to it later when logging in from other devices or networks.

- `UdpSessionName`: Customizes the session name. This only takes effect when `UdpSessionAttach` is set to `yes` or when logging in with the `--attach` argument. If a session with this name already exists on the server, it will attach directly; if not, a new session with this name will be created for automatic attachment in future logins.

### UDP Port Forwarding

When using tssh as the client, UDP port forwarding is supported.

- Command-line `-L` / `-R` options are extended with a `udp/` prefix (the `/` can also be replaced with `:`, `_`, or `-`):

  ```
  -L udp/[bind_address:]port:host:hostport
  -L udp:[bind_address:]port:/remote_socket
  -L udp_/local_socket:host:hostport
  -L udp-/local_socket:/remote_socket

  -R udp/[bind_address:]port:host:hostport
  -R udp:[bind_address:]port:/local_socket
  -R udp_/remote_socket:host:hostport
  -R udp-/remote_socket:/local_socket
  ```

- Configuration is similar to `LocalForward` and `RemoteForward`, with an added `UDP` prefix (case-insensitive):

  ```
  UdpLocalForward [bind_address:]port host:hostport
  UdpLocalForward [bind_address:]port /remote_socket
  UdpLocalForward /local_socket host:hostport
  UdpLocalForward /local_socket /remote_socket

  UdpRemoteForward [bind_address:]port host:hostport
  UdpRemoteForward [bind_address:]port /local_socket
  UdpRemoteForward /remote_socket host:hostport
  UdpRemoteForward /remote_socket /local_socket
  ```

- `ForwardUdpTimeout`: Sets the idle timeout for UDP forwarding sessions; the corresponding forwarding session will be cleared automatically if no data is sent or received within this period to free resources. Default is 5 minutes.

### Developer Guide: Building Custom SSH Services

**tsshd** is more than just a binary program; it is a powerful framework that allows you to build custom SSH applications with **seamless roaming** and **low-latency** capabilities.

#### A. Quick Start: Custom Business Logic

You can easily inject your own interaction logic into an SSH session using the middleware mechanism provided by `tsshd`.

```go
func main() {
    // Use tsshd.RunMain as the entry point and inject custom middleware
    code, err := tsshd.RunMain(
        tsshd.WithMiddleware(func(next tsshd.Handler) tsshd.Handler {
            return func(sess tsshd.Session) {
                term := term.NewTerminal(sess, "Enter your name: ")
                name, _ := term.ReadLine()
                fmt.Fprintf(sess, "Hello, %s! This is a custom SSH service with roaming support.\r\n", name)
            }
        }),
    )
    if err != nil {
        fmt.Fprintf(os.Stderr, "%v\n", err)
    }
    os.Exit(code)
}
```

**How it Works:**

1.  **OpenSSH Bootstrapping**: When a client connects using `tssh --udp`, it first logs in via the standard SSH protocol.
2.  **Process Spawning**: OpenSSH spawns your custom binary on the server side.
3.  **Protocol Switch**: The program starts and listens on a random UDP port, sends the session keys back to the client, and then the client switches to the QUIC/KCP protocol to communicate directly with the program.

> **Note**: If your binary is not in the system `PATH`, you must specify the path on the client side using the `TsshdPath` config or the `--tsshd-path` CLI option.

#### B. Advanced: Building Integrated Servers with Wish

If you don't want to rely on the system's OpenSSH to spawn processes, or if you want to build a pure, single-binary custom SSH server, you can combine [Wish](https://github.com/charmbracelet/wish) (based on [gliderlabs/ssh](https://github.com/gliderlabs/ssh)) with `tsshd`.

In this mode, your program can play two roles simultaneously:

- **Regular SSH Server (TCP)**: Listens on port 22 or a custom port to handle the initial login.
- **tsshd Server (UDP)**: Handles roaming, reconnection, and low-latency transmission.

##### Core Design Concept: Adapter Pattern

To reuse business logic (such as terminal interaction) across both Wish and `tsshd`, you can define a unified `Session` interface to abstract away the underlying differences:

```go
// Unified Session interface to make business logic shared between Wish (TCP) and tsshd (UDP)
type Session = tsshd.Session

func handleBusiness(sess Session) {
    fmt.Fprintf(sess, "Current session type: %T\r\n", sess)
    // Write your business logic here...
}
```

##### Session Handoff (Process Handoff)

When Wish receives a request from the client to start `tsshd`, you can use `exec.Command` to re-execute the current binary (with `tsshd` arguments) to achieve a seamless switch from a "standard SSH handshake" to "UDP low-latency transmission":

1.  **Instruction Detection**: Capture the client's request to execute `tsshd` within the Wish middleware.
2.  **Secondary Launch**: Start a sub-process locally on the server (running the current program in `tsshd` mode).
3.  **Environment Inheritance**: Pass current connection info (like `SSH_CONNECTION`) to the sub-process.

#### C. Why Choose This Architecture?

- **Development Efficiency**: Leverage the Go ecosystem to write SSH services as easily as writing Web middleware.
- **Hybrid Deployment**: Package both client (`tssh`) and server (`tsshd`) logic into a single binary, simplifying distribution.
- **Superior Experience**: Users enjoy the security of traditional SSH alongside a smooth experience in high-latency or unstable network environments, including automatic reconnection and seamless roaming.

#### D. Examples

To help you get started quickly, we provide fully working sample code in the [`examples/`](https://github.com/trzsz/tsshd/tree/main/examples) directory. You can use these as templates for your own custom SSH services.

- **[examples/hello](https://github.com/trzsz/tsshd/tree/main/examples/hello)**
  The most basic implementation. It demonstrates how to use `tsshd.WithMiddleware` to intercept an SSH session, print a greeting, and read user input using the `term` package. Perfect for building interactive CLI tools.

- **[examples/sshd](https://github.com/trzsz/tsshd/tree/main/examples/sshd)**
  A more comprehensive example showing how to handle actual command execution. It demonstrates how to properly route PTY (interactive) and Direct (batch) execution flows, handle terminal window resizing, and stream standard I/O directly to local sub-processes.

- **[examples/wish](https://github.com/trzsz/tsshd/tree/main/examples/wish)**
  A complete showcase of the **Hybrid Architecture** mentioned above. It implements the adapter pattern to unify the `Session` interface, allowing the same business logic to run seamlessly across a traditional TCP SSH server (Wish) and the low-latency UDP `tsshd` server, complete with the process handoff mechanism.

> **Tip**: You can run these examples locally and test them using the `tssh` client to experience the low-latency and roaming features firsthand!

### Screenshot

![tsshd attach session](https://trzsz.github.io/images/tsshd_attach.gif)

![tsshd auto reconnect](https://trzsz.github.io/images/tsshd_conn.gif)

### Contact

Feel free to email the author <lonnywong@qq.com>, or create an [issue](https://github.com/trzsz/tsshd/issues). Welcome to join the QQ group: 318578930.

### Sponsor

[❤️ Sponsor trzsz ❤️](https://github.com/trzsz), buy the author a drink 🍺 ? Thank you for your support!
