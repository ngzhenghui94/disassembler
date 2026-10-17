import Foundation

/// A macOS/iOS `.ips` crash report (JSON header line + JSON body).
public struct CrashReport: Sendable {
    public struct Image: Sendable, Decodable, Hashable {
        public let name: String?
        public let path: String?
        public let uuid: String?
    }

    public struct Frame: Sendable, Decodable, Hashable {
        public let imageIndex: Int?
        public let imageOffset: UInt64?
        public let symbol: String?
        public let symbolLocation: UInt64?
    }

    public struct Thread: Sendable, Identifiable {
        public let id: Int
        public let title: String
        public let crashed: Bool
        public let frames: [Frame]
    }

    public let title: String
    public let exception: String
    public let procPath: String?
    public let images: [Image]
    public let threads: [Thread]   // crashed thread / exception backtrace first

    private struct Header: Decodable { let app_name: String?; let app_version: String?; let bug_type: String? }
    private struct Body: Decodable {
        struct Exc: Decodable { let type: String?; let signal: String?; let subtype: String? }
        struct T: Decodable { let triggered: Bool?; let name: String?; let queue: String?; let frames: [Frame]? }
        let procName: String?
        let procPath: String?
        let exception: Exc?
        let asi: [String: [String]]?
        let usedImages: [Image]?
        let threads: [T]?
        let lastExceptionBacktrace: [Frame]?
    }

    public init(data: Data) throws {
        let split = data.firstIndex(of: UInt8(ascii: "\n")) ?? data.endIndex
        let header = try? JSONDecoder().decode(Header.self, from: data[..<split])
        let bodyData = split < data.endIndex ? data[data.index(after: split)...] : data[...]
        guard let body = try? JSONDecoder().decode(Body.self, from: bodyData), let rawThreads = body.threads else {
            throw MachOError(message: "Not an .ips crash report (only the JSON format from macOS 12 / iOS 15 and later is supported)")
        }
        title = [header?.app_name ?? body.procName, header?.app_version].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
        let exc = body.exception
        exception = ([[exc?.type, exc?.signal].compactMap { $0 }.joined(separator: " "), exc?.subtype ?? ""]
            + (body.asi?.values.flatMap { $0 } ?? [])).filter { !$0.isEmpty }.joined(separator: "\n")
        procPath = body.procPath
        images = body.usedImages ?? []

        var threads: [Thread] = []
        if let bt = body.lastExceptionBacktrace {
            threads.append(Thread(id: -1, title: "Last Exception Backtrace", crashed: true, frames: bt))
        }
        for (i, t) in rawThreads.enumerated() {
            let name = [t.name, t.queue].compactMap { $0 }.joined(separator: " · ")
            threads.append(Thread(id: i, title: "Thread \(i)" + (name.isEmpty ? "" : " — \(name)") + (t.triggered == true ? " (crashed)" : ""),
                                  crashed: t.triggered == true, frames: t.frames ?? []))
        }
        // Keep the exception backtrace first, then the crashed thread, then the rest in order.
        self.threads = threads.filter { $0.id == -1 } + threads.filter { $0.id >= 0 && $0.crashed } + threads.filter { $0.id >= 0 && !$0.crashed }
    }

    public func image(of frame: Frame) -> Image? {
        guard let i = frame.imageIndex, images.indices.contains(i) else { return nil }
        return images[i]
    }

    /// The frame's address in this binary's own (unslid) address space, if the frame belongs to it.
    public func address(of frame: Frame, in macho: MachO) -> UInt64? {
        guard let uuid = macho.uuid, let off = frame.imageOffset,
              image(of: frame)?.uuid?.uppercased() == uuid.uuidString else { return nil }
        return macho.textBase &+ off
    }

    /// Whether any image in the report is exactly this build.
    public func contains(_ macho: MachO) -> Bool {
        guard let uuid = macho.uuid else { return false }
        return images.contains { $0.uuid?.uppercased() == uuid.uuidString }
    }
}
