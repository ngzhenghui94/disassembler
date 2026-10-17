// Draws Resources/AppIcon.icns: run `swift scripts/make-icon.swift` from the repo root.
import AppKit

func render(_ px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                               hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = CGFloat(px) / 1024
    // macOS icon grid: 824pt tile centered in a 1024 canvas.
    let tile = NSRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    let shape = NSBezierPath(roundedRect: tile, xRadius: 185 * s, yRadius: 185 * s)
    NSGradient(colors: [NSColor(red: 0.16, green: 0.19, blue: 0.27, alpha: 1), NSColor(red: 0.05, green: 0.06, blue: 0.09, alpha: 1)])!
        .draw(in: shape, angle: -90)
    NSColor.white.withAlphaComponent(0.08).setStroke()
    shape.lineWidth = 4 * s
    shape.stroke()

    let font = NSFont.monospacedSystemFont(ofSize: 150 * s, weight: .bold)
    ("0x" as NSString).draw(at: NSPoint(x: 190 * s, y: 640 * s),
                            withAttributes: [.font: font, .foregroundColor: NSColor(red: 0.38, green: 0.78, blue: 1, alpha: 1)])

    // Current-instruction highlight behind the third row.
    NSColor.systemGreen.withAlphaComponent(0.18).setFill()
    NSBezierPath(roundedRect: NSRect(x: 150 * s, y: 342 * s, width: 724 * s, height: 82 * s), xRadius: 20 * s, yRadius: 20 * s).fill()
    // Instruction rows: mnemonic (blue), operands (white), comment (green).
    let rows: [(CGFloat, [(CGFloat, CGFloat, NSColor)])] = [
        (540, [(250, 110, .systemBlue), (390, 200, .white.withAlphaComponent(0.75))]),
        (450, [(250, 90, .systemBlue), (370, 260, .white.withAlphaComponent(0.75))]),
        (360, [(250, 110, .systemBlue), (390, 150, .white.withAlphaComponent(0.75)), (570, 170, .systemGreen)]),
        (270, [(250, 70, .systemBlue), (350, 230, .white.withAlphaComponent(0.75))]),
    ]
    for (y, bars) in rows {
        for (x, w, c) in bars {
            c.setFill()
            NSBezierPath(roundedRect: NSRect(x: x * s, y: y * s, width: w * s, height: 46 * s), xRadius: 23 * s, yRadius: 23 * s).fill()
        }
    }
    // Breakpoint on the highlighted row.
    NSColor.systemRed.setFill()
    NSBezierPath(ovalIn: NSRect(x: 172 * s, y: 356 * s, width: 54 * s, height: 54 * s)).fill()

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let iconset = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    try render(size).write(to: iconset.appendingPathComponent("icon_\(size)x\(size).png"))
    try render(size * 2).write(to: iconset.appendingPathComponent("icon_\(size)x\(size)@2x.png"))
}
try FileManager.default.createDirectory(at: URL(fileURLWithPath: "Resources"), withIntermediateDirectories: true)
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", iconset.path, "-o", "Resources/AppIcon.icns"]
try p.run()
p.waitUntilExit()
print(p.terminationStatus == 0 ? "Wrote Resources/AppIcon.icns" : "iconutil failed")
