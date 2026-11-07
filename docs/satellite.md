# Private satellite build

The private satellite build comes from
[nosini/xwayland-satellite](https://github.com/nosini/xwayland-satellite).
Its popup lifetime fixes and regression tests are maintained in that fork.

Build the remote fork and install the launcher:

```sh
./build-satellite.sh
./install.sh
```

Building needs Git, Cargo and Rust, Clang, pkg-config, and the development
packages for XCB and xcb-util-cursor. Xwayland is required at runtime.
Build on the machine where it will run, or with compatible libraries.

The script fetches the reviewed fork commit pinned in `build-satellite.sh`
from GitHub, checks that it got that commit, builds its locked release
dependencies, and writes `sandbox-xwayland-satellite` and
`satellite-LICENSE` beside the launcher. Build output stays in
`.satellite-build/`; `SATELLITE_BUILD_DIR` selects another build directory.
These generated files are not tracked by Git.

The checkout finds the binary directly. `install.sh` copies it into
`~/.local/lib/sandbox-game/`. Reinstalling without a built helper keeps the
installed helper. To return to the system satellite, remove
`sandbox-xwayland-satellite` from the checkout and that installed folder.
Uninstalling sandbox-game removes its installed helper and license.

The launcher mounts the helper read-only inside the sandbox and protects its
internal Wayland socket with the same Landlock rules as the system backend.
