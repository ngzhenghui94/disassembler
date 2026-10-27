import DisasmCore
import SwiftUI
import UniformTypeIdentifiers

@main
struct DisassemblerApp: App {
    @State private var doc = Document()
    @AppStorage("showBytes") private var showBytes = false
    @AppStorage("showPseudocode") private var showPseudocode = false

    var body: some Scene {
        Window("Disassembler", id: "main") {
            ContentView().environment(doc)
        }
        .defaultSize(width: 1320, height: 840)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open…") { doc.showImporter = true }.keyboardShortcut("o")
                Menu("Open Recent") {
                    ForEach(doc.recents, id: \.self) { url in Button(url.lastPathComponent) { doc.open(url) } }
                    Divider()
                    Button("Clear Menu") { doc.clearRecents() }.disabled(doc.recents.isEmpty)
                }
            }
            CommandGroup(after: .toolbar) {
                Toggle("Show Instruction Bytes", isOn: $showBytes).keyboardShortcut("b", modifiers: [.command, .shift])
                Toggle("Show Pseudocode", isOn: $showPseudocode).keyboardShortcut(.return, modifiers: .option)
            }
            CommandMenu("Navigate") {
                Button("Back") { doc.back() }.keyboardShortcut("[").disabled(doc.history.isEmpty)
                Button("Go to Address or Name…") { doc.gotoRequests += 1 }.keyboardShortcut("l").disabled(doc.analysis == nil)
            }
            CommandMenu("Debug") {
                Button("Run") { doc.launch() }.keyboardShortcut("r").disabled(!doc.canDebug)
                Button("Attach to Running App") { doc.attach() }.keyboardShortcut("r", modifiers: [.command, .shift])
                    .disabled(!doc.canDebug)
                Divider()
                Button(doc.isRunning ? "Pause" : "Continue") { doc.send(doc.isRunning ? "pause" : "continue") }
                    .keyboardShortcut("y", modifiers: [.command, .control]).disabled(doc.session == nil)
                // Xcode's keys: F6/F7/F8 step by source line, with ⌃ by instruction.
                Group {
                    Button("Step Over") { doc.send("next") }.keyboardShortcut(fKey(6), modifiers: [])
                    Button("Step Into") { doc.send("step") }.keyboardShortcut(fKey(7), modifiers: [])
                    Button("Step Out") { doc.send("finish") }.keyboardShortcut(fKey(8), modifiers: [])
                    Button("Step Over Instruction") { doc.send("nexti") }.keyboardShortcut(fKey(6), modifiers: .control)
                    Button("Step Into Instruction") { doc.send("stepi") }.keyboardShortcut(fKey(7), modifiers: .control)
                }
                .disabled(doc.session == nil || doc.isRunning)
                Button("Stop") { doc.stopDebugging(); doc.debugState = "Stopped" }
                    .keyboardShortcut(".").disabled(doc.session == nil)
            }
        }
    }
}

func hex(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

/// F1 is NSF1FunctionKey (0xF704); the rest follow in order.
func fKey(_ n: Int) -> KeyEquivalent { KeyEquivalent(Character(UnicodeScalar(0xF703 + n)!)) }

enum SidebarTab: String, CaseIterable {
    case procedures = "Procs", imports = "Imports", strings = "Strings", debug = "Debug", crash = "Crash", info = "Info"
}

struct ContentView: View {
    @Environment(Document.self) private var doc
    @State private var query = ""
    @State private var gotoText = ""
    @State private var gotoFailed = false
    @FocusState private var gotoFocused: Bool

    var body: some View {
        @Bindable var doc = doc
        NavigationSplitView {
            VStack(spacing: 6) {
                Picker("", selection: $doc.sidebarTab) {
                    ForEach(SidebarTab.allCases, id: \.self) { Text($0.rawValue) }
                }
                .pickerStyle(.segmented).labelsHidden()
                TextField("Filter", text: $query).textFieldStyle(.roundedBorder)
                if let a = doc.analysis {
                    Sidebar(analysis: a, tab: doc.sidebarTab, query: query)
                } else if doc.sidebarTab == .crash {
                    List { CrashSection(analysis: nil) }.listStyle(.sidebar)
                } else {
                    Spacer()
                }
            }
            .padding(.horizontal, 8)
            .navigationSplitViewColumnWidth(min: 280, ideal: 330)
        } detail: {
            if doc.debugState.isEmpty {
                detail
            } else {
                VSplitView {
                    detail.frame(minHeight: 200)
                    DebugPanel().frame(minHeight: 150, idealHeight: 260)
                }
            }
        }
        .navigationTitle(doc.url?.lastPathComponent ?? "Disassembler")
        .navigationSubtitle(doc.arch)
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button { doc.back() } label: { Image(systemName: "chevron.left") }
                    .disabled(doc.history.isEmpty).help("Back (⌘[)")
            }
            if doc.bundleBinaries.count > 1, let bundle = doc.bundleURL {
                ToolbarItem {
                    Picker("Binary", selection: Binding(
                        get: { doc.bundleBinaries.first { $0.resolvingSymlinksInPath() == doc.url?.resolvingSymlinksInPath() } ?? doc.bundleBinaries[0] },
                        set: { doc.openBinary($0) })) {
                        ForEach(doc.bundleBinaries, id: \.self) { Text(relativePath($0, in: bundle)).tag($0) }
                    }
                    .frame(maxWidth: 260)
                    .help("Binaries inside this bundle")
                }
            }
            if doc.slices.count > 1 {
                ToolbarItem {
                    Picker("Architecture", selection: Binding(get: { doc.arch }, set: { doc.load($0) })) {
                        ForEach(doc.slices) { Text($0.arch).tag($0.arch) }
                    }
                }
            }
            ToolbarItem {
                TextField("Go to address or name", text: $gotoText)
                    .frame(width: 200)
                    .foregroundStyle(gotoFailed ? .red : .primary)
                    .onSubmit { gotoFailed = !doc.goTo(gotoText) }
                    .onChange(of: gotoText) { gotoFailed = false }
                    .focused($gotoFocused)
                    .onChange(of: doc.gotoRequests) { gotoFocused = true }
                    .help("Hex address or exact symbol name (⌘L)")
            }
            ToolbarItem {
                Button { doc.launch() } label: { Image(systemName: "play.fill") }
                    .disabled(!doc.canDebug).help("Run the configured executable under the debugger (⌘R)")
            }
            ToolbarItem {
                Button { doc.attach() } label: { Image(systemName: "link") }
                    .disabled(!doc.canDebug).help("Attach to the configured process (⇧⌘R)")
            }
            ToolbarItem {
                Button { doc.showImporter = true } label: { Image(systemName: "folder") }.help("Open a binary, .app or .ips crash report (⌘O)")
            }
        }
        .fileImporter(isPresented: $doc.showImporter, allowedContentTypes: [.item, .applicationBundle]) { result in
            if case .success(let url) = result { doc.open(url) }
        }
        .onAppear {
            // `open -a Disassembler --args /path/to/App.app [/path/to/crash.ips]`
            if doc.url == nil { CommandLine.arguments.dropFirst().forEach { doc.open(URL(fileURLWithPath: $0)) } }
        }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first else { return false }
            doc.open(url)
            return true
        }
    }

    private func relativePath(_ u: URL, in bundle: URL) -> String {
        let base = bundle.resolvingSymlinksInPath().path + "/"
        let p = u.resolvingSymlinksInPath().path
        let rel = p.hasPrefix(base) ? String(p.dropFirst(base.count)) : u.lastPathComponent
        return rel.hasPrefix("Contents/") ? String(rel.dropFirst("Contents/".count)) : rel
    }

    @ViewBuilder private var detail: some View {
        if let error = doc.error {
            ContentUnavailableView("Can't analyze this file", systemImage: "exclamationmark.triangle", description: Text(error))
        } else if doc.loading {
            ProgressView("Disassembling \(doc.arch)…").frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let a = doc.analysis {
            switch doc.destination {
            case .code(let addr):
                if let f = a.function(containing: addr) {
                    ProcedureView(analysis: a, function: f, focus: addr)
                } else {
                    ContentUnavailableView("No procedure at \(hex(addr))", systemImage: "questionmark")
                }
            case .xrefs(let addr, let title):
                XrefsView(analysis: a, address: addr, title: title)
            case nil:
                ContentUnavailableView("No code", systemImage: "doc")
            }
        } else {
            ContentUnavailableView {
                Label("Open a Mach-O binary, Android .so, .app or crash report", systemImage: "cpu")
            } description: {
                Text("⌘O, or drop a file here. Your own debug builds keep their symbols.")
            } actions: {
                let recent = doc.recents.filter { FileManager.default.fileExists(atPath: $0.path) }.prefix(5)
                VStack(spacing: 18) {
                    Button("Open…") { doc.showImporter = true }.controlSize(.large)
                    if !recent.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Recent").font(.caption).foregroundStyle(.secondary)
                            ForEach(Array(recent), id: \.self) { url in
                                Button { doc.open(url) } label: {
                                    Label(url.lastPathComponent, systemImage: url.pathExtension == "ips" ? "exclamationmark.triangle" : "app")
                                }
                                .buttonStyle(.link)
                                .help(url.path)
                            }
                        }
                    }
                }
            }
        }
    }
}

struct Sidebar: View {
    @Environment(Document.self) private var doc
    let analysis: Analysis
    let tab: SidebarTab
    let query: String

    private func matches(_ s: String) -> Bool { query.isEmpty || s.localizedCaseInsensitiveContains(query) }

    var body: some View {
        let a = analysis
        let current = currentFunction
        ScrollViewReader { proxy in
            List {
                switch tab {
                case .procedures:
                    ForEach(a.functions.filter { matches($0.name) }) { f in
                        row(f.name, hex(f.start), selected: f.start == current) { doc.go(.code(f.start)) }
                    }
                case .imports:
                    ForEach(a.imports.filter { matches($0.name) }) { i in
                        row(i.name, "\(a.xrefs[i.stub]?.count ?? 0) refs") { doc.go(.xrefs(i.stub, i.name)) }
                    }
                case .strings:
                    ForEach(a.strings.filter { matches($0.value) }) { s in
                        row(s.value, "\(a.xrefs[s.address]?.count ?? 0) refs") { doc.go(.xrefs(s.address, "\"\(s.value)\"")) }
                    }
                case .debug:
                    DebugSettingsSection()
                case .crash:
                    CrashSection(analysis: a)
                case .info:
                    InfoSection(macho: a.macho, analysis: a)
                }
            }
            .listStyle(.sidebar)
            .onChange(of: current) { if tab == .procedures, let current { proxy.scrollTo(current) } }
        }
    }

    private var currentFunction: UInt64? {
        if case .code(let addr) = doc.destination { return analysis.function(containing: addr)?.start }
        return nil
    }

    private func row(_ title: String, _ detail: String, selected: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Text(title).lineLimit(1).truncationMode(.middle)
                Spacer()
                Text(detail).font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .listRowBackground(selected ? Color.accentColor.opacity(0.2) : nil)
    }
}

struct CrashSection: View {
    @Environment(Document.self) private var doc
    let analysis: Analysis?

    var body: some View {
        if let e = doc.crashError {
            Text(e).foregroundStyle(.red).font(.caption)
        }
        if let r = doc.crash {
            Section("Crash") {
                Text(r.title).font(.headline)
                ForEach(Array(r.exception.split(separator: "\n").enumerated()), id: \.offset) { _, line in
                    Text(line).font(.caption.monospaced()).textSelection(.enabled).help(String(line))
                }
                if analysis == nil {
                    Text("Open the app or binary this report came from to link frames to its code.").font(.caption).foregroundStyle(.secondary)
                } else if let a = analysis, !r.contains(a.macho) {
                    Label("This report is from a different build than the open binary (UUID mismatch), so frames can't be mapped to code.",
                          systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                }
            }
            ForEach(r.threads) { t in
                Section(t.title) {
                    ForEach(Array(t.frames.enumerated()), id: \.offset) { i, f in frameRow(r, i, f) }
                }
            }
        } else if doc.crashError == nil {
            Text("Open a .ips crash report with ⌘O or drop one here. They're in Console → Crash Reports and ~/Library/Logs/DiagnosticReports.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private func frameRow(_ r: CrashReport, _ i: Int, _ f: CrashReport.Frame) -> some View {
        let addr = analysis.flatMap { r.address(of: f, in: $0.macho) }
        let reported = f.symbol.map { $0 + (f.symbolLocation.map { " + \($0)" } ?? "") } ?? f.imageOffset.map { "+" + hex($0) } ?? "?"
        let label = HStack(alignment: .firstTextBaseline) {
            Text("\(i)").foregroundStyle(.secondary).frame(width: 20, alignment: .trailing)
            VStack(alignment: .leading, spacing: 1) {
                Text(addr.flatMap { a in analysis?.name(of: a) } ?? reported).lineLimit(1).truncationMode(.middle)
                Text(r.image(of: f)?.name ?? "?").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .font(.caption.monospaced())
        .contentShape(Rectangle())
        if let addr {
            // Frame 0 is the faulting instruction; deeper frames are return addresses.
            Button { i == 0 ? doc.follow(addr) : doc.goToReturnAddress(addr) } label: { label.foregroundStyle(Color.accentColor) }
                .buttonStyle(.plain)
        } else {
            label.foregroundStyle(.secondary)
        }
    }
}

struct InfoSection: View {
    let macho: MachO
    let analysis: Analysis

    var body: some View {
        Section("Binary") {
            LabeledContent("Architecture", value: macho.arch)
            LabeledContent("Format", value: macho.isELF ? "ELF" : "Mach-O")
            LabeledContent("Type", value: macho.typeName)
            if macho.isELF { Text("Static analysis only. Android libraries cannot run on macOS.").font(.caption).foregroundStyle(.secondary) }
            if let e = macho.entry { LabeledContent("Entry", value: hex(e)) }
            if let u = macho.uuid { LabeledContent("UUID", value: u.uuidString).textSelection(.enabled) }
            LabeledContent("Procedures", value: "\(analysis.functions.count)")
            LabeledContent("Instructions", value: "\(analysis.instructions.count)")
        }
        Section("Sections") {
            ForEach(macho.sections, id: \.self) { s in
                LabeledContent(s.fullName, value: "\(hex(s.addr)) · \(s.size) B").font(.caption.monospaced())
            }
        }
        Section("Linked libraries") {
            ForEach(macho.dylibs, id: \.self) { Text($0).font(.caption).textSelection(.enabled) }
        }
    }
}

struct ProcedureView: View {
    @Environment(Document.self) private var doc
    @AppStorage("showPseudocode") private var showPseudocode = false
    let analysis: Analysis
    let function: Function
    let focus: UInt64

    var body: some View {
        let callers = analysis.xrefs[function.start] ?? []
        let headers = doc.sourceHeaders[function.start] ?? [:]
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(function.name).font(.headline.monospaced()).textSelection(.enabled).lineLimit(2)
                    Spacer()
                    Picker("", selection: $showPseudocode) {
                        Text("Assembly").tag(false)
                        Text("Pseudocode").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .fixedSize()
                    .help("Switch views (⌥↩)")
                }
                Text("\(hex(function.start)) – \(hex(function.end)) · \(function.lines.count) instructions")
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                if !callers.isEmpty {
                    ScrollView(.horizontal) {
                        HStack {
                            Text("Called from:").font(.caption).foregroundStyle(.secondary)
                            ForEach(callers, id: \.self) { src in
                                Button(analysis.name(of: src)) { doc.go(.code(src)) }.font(.caption.monospaced())
                            }
                        }
                    }
                }
            }
            .padding(10)
            Divider()
            if showPseudocode {
                PseudocodeView(analysis: analysis, function: function)
            } else {
                assembly(headers)
            }
        }
        .task(id: "\(function.start)-\(doc.debugInfoReady)") { await doc.loadSource(for: function) }
    }

    private func assembly(_ headers: [UInt64: SourceHeader]) -> some View {
        ScrollViewReader { proxy in
            List(analysis.instructions[function.lines]) { ins in
                InstructionRow(analysis: analysis, ins: ins, source: headers[ins.address],
                               isFocus: ins.address == focus && focus != function.start)
            }
            .listStyle(.plain)
            .font(.system(.body, design: .monospaced))
            .onAppear { proxy.scrollTo(focus, anchor: .center) }
            .onChange(of: focus) { proxy.scrollTo(focus, anchor: .center) }
        }
    }
}

/// Decompiled pseudo-C for one procedure, computed off the main thread.
struct PseudocodeView: View {
    let analysis: Analysis
    let function: Function
    @State private var code: AttributedString?

    var body: some View {
        Group {
            if let code {
                ScrollView([.vertical, .horizontal]) {
                    Text(code)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize()
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                        .padding(12)
                }
            } else {
                ProgressView("Decompiling…").frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .task(id: function.start) {
            code = nil
            let (a, f) = (analysis, function)
            code = await Task.detached { Self.highlight(Decompiler.decompile(a, f)) }.value
        }
    }

    nonisolated static func highlight(_ lines: [String]) -> AttributedString {
        // Strings, comments, keywords, numbers: enough colour to read the structure at a glance.
        let pattern = /"(?:[^"\\]|\\.)*"|@"(?:[^"\\]|\\.)*"|\/\/.*|\b(?:if|else|while|do|return|goto|break|continue|void|int64_t|super)\b|\b(?:0x[0-9a-f]+|\d+)\b|^loc_[0-9a-f]+:/
        var out = AttributedString()
        for (n, line) in lines.enumerated() {
            var rest = Substring(line)
            while let m = rest.firstMatch(of: pattern) {
                out += AttributedString(String(rest[..<m.range.lowerBound]))
                var token = AttributedString(String(m.output))
                let t = m.output
                token.foregroundColor = t.hasPrefix("\"") || t.hasPrefix("@\"") ? .red
                    : t.hasPrefix("//") ? .secondary
                    : t.first?.isNumber == true ? .blue
                    : t.hasPrefix("loc_") ? .orange
                    : .purple
                out += token
                rest = rest[m.range.upperBound...]
            }
            out += AttributedString(String(rest) + (n + 1 < lines.count ? "\n" : ""))
        }
        return out
    }
}

struct InstructionRow: View {
    @Environment(Document.self) private var doc
    @AppStorage("showBytes") private var showBytes = false
    let analysis: Analysis
    let ins: Instruction
    let source: SourceHeader?
    let isFocus: Bool

    var body: some View {
        let refs = analysis.xrefs[ins.address]?.count ?? 0
        let hasBreakpoint = doc.breakpoints.contains(ins.address)
        let isPC = doc.pc == ins.address
        VStack(alignment: .leading, spacing: 2) {
            if let source {
                HStack(spacing: 10) {
                    Text(source.location).foregroundStyle(.purple)
                    Text(source.text).foregroundStyle(.secondary)
                }
                .font(.caption.monospaced())
                .padding(.leading, 26)
                .padding(.top, 4)
            }
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Button { doc.toggleBreakpoint(ins.address) } label: {
                    Image(systemName: isPC ? "arrowtriangle.right.fill" : hasBreakpoint ? "circle.fill" : "circle")
                        .foregroundStyle(isPC ? AnyShapeStyle(.green) : hasBreakpoint ? AnyShapeStyle(.red) : AnyShapeStyle(.quaternary))
                        .opacity(hasBreakpoint && !isPC && !doc.isEnabled(.address(ins.address)) ? 0.35 : 1)
                        .font(.caption)
                        .overlay(alignment: .bottomTrailing) {
                            if isPC && hasBreakpoint { Circle().fill(.red).frame(width: 5, height: 5) }
                        }
                }
                .buttonStyle(.plain)
                .frame(width: 14)
                .help(hasBreakpoint ? "Remove breakpoint" : "Set breakpoint")
                Text(String(ins.address, radix: 16)).foregroundStyle(.secondary)
                if showBytes { Text(ins.bytes).foregroundStyle(.tertiary).frame(width: 130, alignment: .leading).lineLimit(1) }
                Text(ins.mnemonic).foregroundStyle(.blue).frame(width: 64, alignment: .leading)
                if let t = ins.target {
                    Button(analysis.name(of: t)) { doc.follow(t) }.buttonStyle(.link).help(hex(t))
                } else {
                    Text(ins.operands).textSelection(.enabled)
                }
                if !ins.comment.isEmpty {
                    if let ref = ins.dataRefs.last {
                        Button("; " + ins.comment) { doc.go(.xrefs(ref, ins.comment)) }.buttonStyle(.plain).foregroundStyle(.green)
                    } else {
                        Text("; " + ins.comment).foregroundStyle(.green).lineLimit(1)
                    }
                }
                Spacer(minLength: 0)
                if refs > 0 { Text("◂ \(refs)").font(.caption).foregroundStyle(.orange).help("Referenced \(refs)×") }
            }
            .lineLimit(1)
        }
        .id(ins.address)
        .listRowBackground(isPC ? Color.green.opacity(0.22) : isFocus ? Color.yellow.opacity(0.25) : nil)
    }
}

struct DebugSettingsSection: View {
    @Environment(Document.self) private var doc
    @State private var newSymbol = ""

    private func android(_ key: WritableKeyPath<AndroidDebugOptions, String>) -> Binding<String> {
        Binding(get: { (doc.settings.android ?? AndroidDebugOptions())[keyPath: key] }, set: {
            var options = doc.settings.android ?? AndroidDebugOptions()
            options[keyPath: key] = $0
            doc.settings.android = options
        })
    }

    var body: some View {
        @Bindable var doc = doc
        if doc.isAndroid {
            Section("Android device") {
                TextField("Device serial (automatic if one device)", text: android(\.device))
                TextField("Debuggable package (optional run-as)", text: android(\.package))
                TextField("PID to attach", text: android(\.pid))
                TextField("Device executable path to launch", text: android(\.remotePath))
                TextField("ADB path (automatic)", text: android(\.adbPath))
                TextField("Android lldb-server path (ABI must match)", text: android(\.serverPath))
                HStack {
                    Button("Attach") { doc.attach() }
                    Button("Launch") { doc.launch() }
                }.buttonStyle(.borderless)
                Text("Open the matching .so locally. Launch its host executable or attach to its process. Stop detaches attached processes.").font(.caption).foregroundStyle(.secondary).lineLimit(nil).fixedSize(horizontal: false, vertical: true)
            }.textFieldStyle(.roundedBorder)
        }
        Section("Breakpoints") {
            if doc.allBreakpoints.isEmpty {
                Text("Click the circle beside an instruction, or add a function name below.").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(doc.allBreakpoints, id: \.self) { b in
                HStack(spacing: 6) {
                    Toggle("", isOn: Binding(get: { doc.isEnabled(b) }, set: { doc.setEnabled(b, $0) }))
                        .labelsHidden().toggleStyle(.checkbox)
                    Button {
                        if case .address(let a) = b { doc.follow(a) }
                    } label: {
                        Label(doc.label(b), systemImage: { switch b {
                        case .address: "number"
                        case .symbol: "function"
                        case .exception: "exclamationmark.octagon"
                        } }())
                        .lineLimit(1).truncationMode(.middle)
                    }
                    .buttonStyle(.plain)
                    Spacer()
                    Button { doc.remove(b) } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless).help("Remove breakpoint")
                }
                .foregroundStyle(doc.isEnabled(b) ? .primary : .secondary)
            }
            TextField("Break on function, e.g. malloc_error_break", text: $newSymbol)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    let name = newSymbol.trimmingCharacters(in: .whitespaces)
                    if !name.isEmpty { doc.add(.symbol(name)); newSymbol = "" }
                }
        }
        Section("Stop when thrown") {
            ForEach(doc.isAndroid ? ["cpp"] : ["objc", "swift", "cpp"], id: \.self) { lang in
                Toggle(Document.exceptionLabels[lang] ?? lang, isOn: Binding(
                    get: { doc.settings.exceptions.contains(lang) },
                    set: { $0 ? doc.add(.exception(lang)) : doc.remove(.exception(lang)) }))
            }
        }
        Section("Launch options") {
            TextField("Arguments", text: $doc.settings.arguments).textFieldStyle(.roundedBorder)
                .help("Passed to the app when you run it. Quote arguments that contain spaces.")
            if !doc.isAndroid {
            Text("Environment, one KEY=VALUE per line").font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $doc.settings.environment)
                .font(.caption.monospaced())
                .frame(height: 54)
                .scrollContentBackground(.hidden)
                .background(.background.opacity(0.4), in: RoundedRectangle(cornerRadius: 5))
            ForEach(DebugSettings.presetVariables, id: \.name) { preset in
                Toggle(preset.name, isOn: Binding(
                    get: { doc.settings.presets.contains(preset.name) },
                    set: { if $0 { doc.settings.presets.insert(preset.name) } else { doc.settings.presets.remove(preset.name) } }))
                    .help("\(preset.help) (\(preset.env))")
            }
            }
            Text("Saved for this app. Takes effect the next time you run it (⌘R).").font(.caption).foregroundStyle(.secondary)
        }
        Section("Frida native traces") {
            TextField("PID", text: $doc.fridaPID)
            TextField("Device ID (USB by default)", text: $doc.fridaDevice)
            TextField("Local forwarded port (optional)", text: $doc.fridaPort)
            TextField("Python with frida installed (automatic)", text: $doc.fridaPython)
            HStack {
                Button("Attach") { doc.attachFrida() }.disabled(doc.tracer != nil)
                Button("Detach") { doc.detachFrida() }.disabled(doc.tracer == nil)
            }.buttonStyle(.borderless)
            TextField("Exported function in this library", text: $doc.fridaSymbol)
            Button("Trace calls") { doc.traceFrida() }.buttonStyle(.borderless).disabled(doc.tracer == nil || doc.fridaSymbol.isEmpty)
            Text("Requires Frida Server or Gadget. Captures raw arguments and return values; detach removes all traces. Agents can also trace module offsets through MCP.").font(.caption).foregroundStyle(.secondary).lineLimit(nil).fixedSize(horizontal: false, vertical: true)
            if !doc.fridaOutput.isEmpty {
                ScrollView([.horizontal, .vertical]) {
                    Text(doc.fridaOutput).font(.caption.monospaced()).lineLimit(nil).fixedSize().textSelection(.enabled)
                }.frame(height: 180)
            }
        }
        .textFieldStyle(.roundedBorder)
        .onReceive(Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()) { _ in doc.refreshFrida() }
    }
}

struct DebugPanel: View {
    @Environment(Document.self) private var doc

    var body: some View {
        let live = doc.session != nil
        let stopped = live && !doc.isRunning
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Circle().fill(!live ? Color.gray : doc.isRunning ? .green : .orange).frame(width: 8, height: 8)
                Text(doc.debugState).font(.callout).lineLimit(1).truncationMode(.tail).textSelection(.enabled)
                Spacer()
                Button { doc.send(doc.isRunning ? "pause" : "continue") } label: {
                    Image(systemName: doc.isRunning ? "pause.fill" : "play.fill")
                }.help(doc.isRunning ? "Pause (⌃⌘Y)" : "Continue (⌃⌘Y)").disabled(!live)
                Group {
                    Button { doc.send("next") } label: { Image(systemName: "arrow.turn.down.right") }.help("Step over (F6, ⌃F6 by instruction)")
                    Button { doc.send("step") } label: { Image(systemName: "arrow.down.to.line") }.help("Step into (F7, ⌃F7 by instruction)")
                    Button { doc.send("finish") } label: { Image(systemName: "arrow.up.to.line") }.help("Step out (F8)")
                }
                .disabled(!stopped)
                Button { doc.stopDebugging(); doc.debugState = "Stopped" } label: { Image(systemName: "stop.fill") }
                    .help("Stop (⌘.)").disabled(!live)
                Button { doc.stopDebugging(); doc.debugState = ""; doc.console = "" } label: { Image(systemName: "xmark") }
                    .help("Close debugger")
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, 10).padding(.vertical, 6)
            Divider()
            HSplitView {
                List(Array(doc.stopFrames.enumerated()), id: \.offset) { i, f in
                    Button { doc.selectFrame(i) } label: {
                        VStack(alignment: .leading, spacing: 1) {
                            Text("\(i)  \(f.function)").lineLimit(1).truncationMode(.middle)
                                .foregroundStyle(f.fileAddr != nil || f.line != nil ? .primary : .secondary)
                            Text([f.module, f.line].compactMap { $0 }.joined(separator: " · ")).font(.caption2).foregroundStyle(.secondary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(!stopped)
                    .listRowBackground(i == doc.selectedFrame && stopped ? Color.accentColor.opacity(0.25) : nil)
                }
                .frame(minWidth: 200)
                .opacity(doc.isRunning ? 0.4 : 1)
                VStack(spacing: 0) {
                    @Bindable var doc = doc
                    Picker("", selection: $doc.inspectorTab) {
                        ForEach(InspectorTab.allCases, id: \.self) { Text($0.rawValue) }
                    }
                    .pickerStyle(.segmented).labelsHidden().padding(6)
                    switch doc.inspectorTab {
                    case .variables: VariablesView()
                    case .registers: RegistersView()
                    case .memory: MemoryView()
                    }
                }
                .frame(minWidth: 280)
                .opacity(doc.isRunning ? 0.4 : 1)   // values are from the last stop
                ScrollView {
                    Text(doc.console.isEmpty ? "Program output appears here." : doc.console)
                        .foregroundStyle(doc.console.isEmpty ? .secondary : .primary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                }
                .defaultScrollAnchor(.bottom)
                .frame(minWidth: 200)
            }
            .font(.caption.monospaced())
        }
    }
}

struct VariablesView: View {
    @Environment(Document.self) private var doc

    var body: some View {
        if doc.variables.isEmpty {
            Text(doc.session == nil ? "Variables appear when the app stops."
                 : "No variables here. Frames without debug info (system code, stripped builds) have none.")
                .foregroundStyle(.secondary).padding().frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        } else {
            List(doc.variables, children: \.children) { v in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(v.name)
                    Text(v.value).foregroundStyle(.orange).textSelection(.enabled).lineLimit(1).truncationMode(.tail)
                    Spacer(minLength: 4)
                    Text(v.type).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                .contextMenu {
                    if doc.variables.contains(v) {   // only top-level names are valid lldb expressions
                        Button("View Memory of \(v.name)") { doc.readMemory("&" + v.name) }
                        if v.type.hasSuffix("*") { Button("View Memory at \(v.name)") { doc.readMemory(v.name) } }
                    }
                }
            }
        }
    }
}

struct RegistersView: View {
    @Environment(Document.self) private var doc

    var body: some View {
        List(doc.registers, id: \.self) { r in
            let changed = doc.changedRegisters.contains(r.first ?? "")
            HStack {
                Text(r.first ?? "").foregroundStyle(.secondary).frame(width: 44, alignment: .leading)
                Text(r.count > 1 ? r[1] : "").textSelection(.enabled)
                    .foregroundStyle(changed ? .orange : .primary)
                    .fontWeight(changed ? .semibold : .regular)
            }
            .help(changed ? "Changed since the last stop" : "")
            .contextMenu { Button("View Memory at \(r.first ?? "")") { doc.readMemory(r.first ?? "") } }
        }
    }
}

struct MemoryView: View {
    @Environment(Document.self) private var doc
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                TextField("Address, register or expression (sp, &count, $x0 + 16)", text: $text)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { doc.readMemory(text) }
                    .onAppear { text = doc.memoryExpression }
                    .onChange(of: doc.memoryExpression) { text = doc.memoryExpression }
                Button("Read") { doc.readMemory(text) }.disabled(text.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(.horizontal, 6)
            if let message = doc.memoryMessage {
                Text(message).foregroundStyle(.red).padding(.horizontal, 6)
            }
            if let m = doc.memory {
                ScrollView([.vertical, .horizontal]) {
                    Text(HexDump.format(m.address, m.bytes)).textSelection(.enabled).padding(6)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else if doc.memoryMessage == nil {
                Text("Right-click a register or variable, or type an address.").foregroundStyle(.secondary).padding(.horizontal, 6)
                Spacer()
            }
        }
    }

}

struct XrefsView: View {
    @Environment(Document.self) private var doc
    let analysis: Analysis
    let address: UInt64
    let title: String

    var body: some View {
        let refs = analysis.xrefs[address] ?? []
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline).textSelection(.enabled).lineLimit(3)
                Text("\(hex(address)) · \(refs.count) references").font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            .padding(10)
            Divider()
            if refs.isEmpty {
                ContentUnavailableView("No code references found", systemImage: "link",
                                       description: Text("References through computed or indirect addresses aren't tracked."))
            } else {
                List(refs, id: \.self) { src in
                    Button { doc.go(.code(src)) } label: {
                        HStack(spacing: 12) {
                            Text(String(src, radix: 16)).foregroundStyle(.secondary)
                            Text(analysis.name(of: src))
                            if let i = analysis.instruction(at: src) {
                                Text("\(i.mnemonic) \(i.operands)").foregroundStyle(.secondary)
                            }
                        }
                        .lineLimit(1)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                .listStyle(.plain)
                .font(.system(.body, design: .monospaced))
            }
        }
    }
}
