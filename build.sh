#!/bin/sh
# Builds build/Disassembler.app; pass --install to replace /Applications/Disassembler.app.
set -eu
cd "$(dirname "$0")"
swift build -c release
APP=build/Disassembler.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
BIN="$(swift build -c release --show-bin-path)"
cp "$BIN/Disassembler" "$BIN/disasm-mcp" "$APP/Contents/MacOS/"   # disasm-mcp: REA provider (see README)
cp Info.plist "$APP/Contents/"
cp Resources/AppIcon.icns Resources/rea-ida-mcp.json "$APP/Contents/Resources/"
codesign --force --sign - "$APP"
if [ "${1:-}" = "--install" ]; then
  rm -rf /Applications/Disassembler.app
  ditto "$APP" /Applications/Disassembler.app
  echo "Installed /Applications/Disassembler.app"
fi
