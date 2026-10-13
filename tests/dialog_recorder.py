#!/usr/bin/env python3
"""Record host GUI requests and simulate edits without a display server."""
import json
import os
import runpy
import sys
from pathlib import Path

MODE = sys.argv[1]
if MODE == "check":
    sys.exit(0)
if MODE != "preferences":
    if os.environ.get("DIALOG_RECORD"):
        # The failure window's text arrives on stdin.
        shown = sys.argv[1:] + ([sys.stdin.read()] if MODE == "log" else [])
        Path(os.environ["DIALOG_RECORD"]).write_text(json.dumps(shown))
    sys.exit(int(os.environ.get("DIALOG_EXIT", "0")))

request = json.load(sys.stdin)
Path(os.environ["DIALOG_RECORD"]).write_text(json.dumps(request))
module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "sandbox-game-dialog"))
state = module["Preferences"](request)
if os.environ.get("TEST_LAUNCH_WITH"):
    state.set_runtime("proton" if os.environ["TEST_LAUNCH_WITH"] == "Proton (Windows .exe)" else "auto")
form = json.loads(os.environ.get("TEST_FORM", "[]"))
if not form:
    sys.exit(1)
fields = ["display", "mangohud"]
if state.proton_controls:
    fields += ["proton", "mod_loaders"]
if state.engine == "nwjs":
    fields += ["casefold", "webgl"]
fields += ["net", "scope"]
for key, value in zip(fields, form):
    if not value:
        continue
    if key == "display":
        state.display = next(k for k, label in module["DISPLAY_CHOICES"].items() if label == value)
    elif key == "scope":
        state.scope = {"This game only": "game", "All games (defaults)": "all",
                       "Clear this game's settings": "clear"}[value]
    elif key == "mangohud":
        state.values[key] = "1" if value == "On" else "0"
    elif key == "mod_loaders" or key == "net":
        state.values[key] = "0" if value == "Off" else "1"
    elif key == "proton":
        state.values[key] = "auto" if value == "Newest installed (auto)" else value
    elif key == "casefold":
        state.values[key] = "0" if value == "Match exactly" else "1"
    elif key == "webgl":
        state.values[key] = "vulkan" if value == "Vulkan" else "auto"
# Controls outside the positional form, by key, as the window stores them.
state.values.update(json.loads(os.environ.get("TEST_VALUES", "{}")))
if os.environ.get("TEST_GS_FORM"):
    resolution, full = os.environ["TEST_GS_FORM"].split("\t")
    state.resolution = "" if resolution == "Game default (no override)" else resolution
    state.fullscreen = full == "Yes"
print(json.dumps(state.result()))
