import DisasmCore
import SwiftUI

struct SignatureEditor: View {
    @Environment(Document.self) private var doc
    @Environment(\.dismiss) private var dismiss
    let address: UInt64
    let name: String
    let revision: UUID
    private let hasOverride: Bool
    @State private var returnType: FunctionType
    @State private var parameters: [ParameterRow]
    @State private var error: String?

    private struct ParameterRow: Identifiable {
        let id = UUID()
        var name: String
        var type: FunctionType
    }

    init(address: UInt64, name: String, revision: UUID, signature: FunctionSignature?) {
        self.address = address
        self.name = name
        self.revision = revision
        hasOverride = signature != nil
        _returnType = State(initialValue: signature?.returnType ?? .int64)
        _parameters = State(initialValue: signature?.parameters.map { ParameterRow(name: $0.name, type: $0.type) } ?? [])
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Function Signature").font(.headline)
            Text(name).font(.body.monospaced()).textSelection(.enabled)
            Text("Set the exact parameters in calling order. Types and names update this function and its callers. An empty list means no parameters.")
                .font(.caption).foregroundStyle(.secondary)
            Picker("Return type", selection: $returnType) {
                ForEach(FunctionType.allCases, id: \.self) { Text($0.cName).tag($0) }
            }
            ScrollView {
                VStack(spacing: 8) {
                    ForEach($parameters) { $parameter in
                        HStack {
                            TextField("Parameter name", text: $parameter.name)
                                .accessibilityLabel("Parameter name")
                            Picker("Type", selection: $parameter.type) {
                                ForEach(FunctionType.allCases.filter { $0 != .void }, id: \.self) { Text($0.cName).tag($0) }
                            }.frame(width: 180)
                            Button { parameters.removeAll { $0.id == parameter.id } } label: { Image(systemName: "minus.circle") }
                                .accessibilityLabel("Remove parameter \(parameter.name)")
                        }
                    }
                }
            }.frame(maxHeight: 220)
            Button("Add Parameter") {
                var n = parameters.count
                while parameters.contains(where: { $0.name == "value\(n)" }) { n += 1 }
                parameters.append(ParameterRow(name: "value\(n)", type: .int64))
            }
            Text("Supports integer and pointer types in argument registers. Floating-point, structures, variadic signatures and stack parameters are not supported. Overrides are saved separately for this exact binary; the binary is never modified.")
                .font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Button("Use Inferred Signature") { save(nil) }.disabled(!hasOverride)
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") {
                    do {
                        let args = try parameters.map { try FunctionParameter(name: $0.name, type: $0.type) }
                        save(try FunctionSignature(returnType: returnType, parameters: args))
                    } catch { self.error = error.localizedDescription }
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20).frame(width: 560)
    }

    private func save(_ signature: FunctionSignature?) {
        do { try doc.setSignature(signature, at: address, revision: revision); dismiss() }
        catch { self.error = error.localizedDescription }
    }
}
