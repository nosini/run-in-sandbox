# Private satellite build

The private satellite build comes from
[nosini/xwayland-satellite](https://github.com/nosini/xwayland-satellite).
Its popup lifetime fixes and regression tests are maintained in that fork.

Get the fork's prebuilt helper and install the launcher:

```sh
./get-satellite.sh
./install.sh
```

`get-satellite.sh` pins a reviewed fork commit, the `sandbox-*` release
built from it, and that release's SHA-256. It downloads the release's
x86_64 tarball, refuses it unless the checksum matches and the tarball names
the pinned commit, and writes `sandbox-xwayland-satellite` and
`satellite-LICENSE` beside the launcher. The fork's `Release` workflow builds
the tarball on Ubuntu 24.04; it needs libxcb and xcb-util-cursor at runtime,
and Xwayland.

`./get-satellite.sh --from-source` builds the same pinned commit here
instead, as does any machine other than x86_64. That needs Git, Cargo and
Rust, Clang, pkg-config, and the development packages for XCB and
xcb-util-cursor. Build on the machine where it will run, or with compatible
libraries. Work files stay in `.satellite-build/`; `SATELLITE_BUILD_DIR`
selects another directory. These generated files are not tracked by Git.

To move to a new fork commit, push it with a new `sandbox-*` tag, wait for
its release, and update `COMMIT`, `TAG` and `SHA256` in `get-satellite.sh`
from the release's `SHA256SUMS`.

The checkout finds the binary directly. `install.sh` copies it into
`~/.local/lib/sandbox-game/`. Reinstalling without a built helper keeps the
installed helper. To return to the system satellite, remove
`sandbox-xwayland-satellite` from the checkout and that installed folder.
Uninstalling sandbox-game removes its installed helper and license.

The launcher mounts the helper read-only inside the sandbox and protects its
internal Wayland socket with the same Landlock rules as the system backend.
