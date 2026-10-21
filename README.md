# BB Map Viewer

A standalone live-map window for **Bloodborne on Windows**. It reads your position from the running game
(read-only, nothing is written) and shows it on the floor plans from your own Hunter's Atlas install, so
you can keep the map on a second monitor or as a small always-on-top window next to the game.

> Unofficial. Not affiliated with Hunter's Atlas or any other project. The position offsets and the map
> format come from [Hunter's Atlas](https://github.com/MikeTat1988/HuntersAtlas) and the
> [Bloodborne-Android](https://github.com/ducvd89/Bloodborne-Android) `runtime_atlas.c`.
> This repository contains no game files and no map data.

## Quick start
1. Download `BBMapViewer.exe` from the [latest release](../../releases/latest). The `.sha256` file lets you verify it.
2. Start the game and load into the world, then run `BBMapViewer.exe`.
3. **First run only:** a dialog asks for your `assets.atlaslite` (it is in your Hunter's Atlas folder). Only a
   file with that name is accepted. The path is remembered in `bb_map_viewer.json` next to the exe.

## What it does
- Shows your position and facing arrow on the vector map of the current area, with a trail of where you walked.
- Highlights the floor level you are standing on; other levels are dimmed.
- Shows the name of the current location at the top left.
- Starts as a small window (about a third of the screen height) in the **bottom-right corner** of your main
  screen, with **Always On Top** already on.
- When it first connects, it switches focus to the game window, like Alt-Tab.
- Teaches itself the arrow direction from how you move: walk around for a few seconds on first use.

## Menu and shortcuts
| Action | Menu item | Key |
|---|---|---|
| Full screen on the **external monitor** (if you have one, otherwise the current monitor); press again to leave | Full Screen (F) | **F** (**Esc** also leaves) |
| Keep the window above other windows | Always On Top (A) | **A** |
| Quit | Quit (Q) | **Q** |
| Zoom | | mouse wheel, **+** / **-** |
| Clear the trail | | **T** |
| Show lamp names (all lamps, including undiscovered) | | **L** |
| Flip north/south if the map looks upside down | | **V** |
| Re-learn the arrow direction (then walk around) | | **C** |
| Rotate / mirror the arrow by hand | | **R** / **M** |

In full screen the menu bar is replaced by a bar that appears when you move the mouse to the top edge of the
screen, with the same three actions.

**Keyboard focus:** after going full screen the viewer hands focus back to the game, so the shortcut keys only
work while the viewer window has focus. Click the viewer first, or use the top-edge bar with the mouse. This
also keeps Esc from opening the game's menu while the viewer is in front.

## Tips
- Put the game on your main monitor and the viewer on the second one, then press **F**.
- Prefer a corner overlay? Leave it in windowed mode with Always On Top on. You can drag and resize it.
- Settings (zoom, always-on-top, arrow calibration, map path) are saved in `bb_map_viewer.json`. Delete the
  `"maps"` line in it to be asked for the map file again.

## Troubleshooting
- **"searching for the game..." never goes away:** make sure the game is running and loaded in. Try starting
  from a terminal with `BBMapViewer.exe --proc <name>` using the game's process name from Task Manager.
- **No map, only a grid:** the map file was not selected. See the settings tip above.
- **Arrow points the wrong way:** press **C** and walk around, or fix it with **R** and **M**.
- **Crash:** the error is written to `bb_map_viewer_error.log` next to the exe.
- **Windows Defender / antivirus flags the exe:** PyInstaller exes that read another process's memory are often
  flagged. Build from source if that worries you.

## Limits
No discovered-lamp tracking, fast travel, pickups or NPC markers. The map resolution and floors come straight
from the Atlas data. Only the 1.09 game build is supported.

## Build from source
Needs Python 3.8+ with tkinter.
```
python -m pip install pillow
python bb_map_viewer.py --maps "C:\path\to\assets.atlaslite"
```
To build the exe yourself, run `build_exe.bat` (output in `dist\BBMapViewer.exe`).

## Releases
Push a tag and GitHub Actions builds and publishes the exe:
```
git tag v1.0.1
git push origin v1.0.1
```
Tags with a hyphen (for example `v1.1.0-beta1`) become pre-releases.
