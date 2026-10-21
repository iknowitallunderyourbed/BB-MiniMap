# BB Map Viewer

Standalone live-map window for Bloodborne on Windows. It reads the player position from the running
game (read-only) and draws it on the floor plans from your own Hunter's Atlas install, so you can keep
the map on a second monitor or as a small always-on-top window.

Unofficial and not affiliated with Hunter's Atlas or any other project. Position offsets and the map
format come from [Hunter's Atlas](https://github.com/MikeTat1988/HuntersAtlas) and the
[Bloodborne-Android](https://github.com/ducvd89/Bloodborne-Android) `runtime_atlas.c`.

## Use
1. Download `BBMapViewer.exe` from the latest release (check the `.sha256` if you like).
2. Start the game and load in, then run the exe.
3. First run only: pick your `assets.atlaslite` (from your Hunter's Atlas folder). The choice is saved
   in `bb_map_viewer.json` next to the exe.

Keys: **F** full screen (external monitor if any; F or Esc leaves), **A** always on top, **Q** quit,
wheel/+/- zoom, **T** clear trail, **L** lamp names, **V** flip north/south, **C** re-learn arrow.

This repo contains no game files and no map data. You need your own copy of the game and Atlas.

## Build locally
`build_exe.bat` (needs Python 3.8+ with tkinter), or run `python bb_map_viewer.py` after
`python -m pip install pillow`.

## Release
Tag and push: `git tag v1.0.1 && git push origin v1.0.1`. GitHub Actions builds the exe and publishes
a release with notes generated from the commits. Tags containing a hyphen (`v1.1.0-beta1`) become
pre-releases.

Antivirus tools sometimes flag PyInstaller exes that read other processes' memory. Build from source
if that worries you.
