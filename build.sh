#!/bin/sh
# Builds build/Disassembler.app; pass --install to replace /Applications/Disassembler.app.
set -eu
cd "$(dirname "$0")"
swift build -c release --product Disassembler
APP=build/Disassembler.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$(swift build -c release --show-bin-path)/Disassembler" "$APP/Contents/MacOS/"
cp Info.plist "$APP/Contents/"
cp Resources/AppIcon.icns "$APP/Contents/Resources/"
codesign --force --sign - "$APP"
if [ "${1:-}" = "--install" ]; then
  rm -rf /Applications/Disassembler.app
  ditto "$APP" /Applications/Disassembler.app
  echo "Installed /Applications/Disassembler.app"
fi
