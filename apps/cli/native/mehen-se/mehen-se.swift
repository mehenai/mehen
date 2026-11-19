// mehen-se: Secure Enclave device key helper for the Mehen CLI.
//
// The private key never leaves the Secure Enclave. What we store on disk is the
// CryptoKit dataRepresentation: an opaque blob wrapped by the Secure Enclave of
// this machine, useless anywhere else. No keychain item is created.
//
//   mehen-se create --out <path> [--user-presence]
//   mehen-se pubkey --key <path>
//   mehen-se sign --key <path> [--no-interaction] < data
//   mehen-se wrap --key <path> [--create-if-missing] < secret
//   mehen-se unwrap --key <path> < envelope
//   mehen-se available
//
// Output: JWK JSON (create, pubkey) or base64url of the raw 64-byte r||s ECDSA
// signature over SHA-256(data) (sign). Errors go to stderr.
//
// wrap and unwrap use a second kind of key, a Secure Enclave P-256
// key-agreement key, to seal a small secret (the local vault's root key) so
// only this Mac's enclave can open it: an ephemeral P-256 key, ECDH with the
// enclave key's public key, HKDF-SHA256 and AES-256-GCM. wrap prints a JSON
// envelope { v, epk, nonce, ct, tag } (base64url fields); unwrap prints the
// secret's bytes exactly. The secret is written to stdout only.
// Exit codes: 0 ok, 1 operation failed or Secure Enclave unavailable, 2 usage.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

let usageText = """
    usage:
      mehen-se create --out <path> [--user-presence]
      mehen-se pubkey --key <path>
      mehen-se sign --key <path> [--no-interaction]   (data on stdin)
      mehen-se wrap --key <path> [--create-if-missing]   (secret on stdin)
      mehen-se unwrap --key <path>   (envelope on stdin)
      mehen-se available
    """

let wrapInfo = Data("mehen-se wrap v1".utf8)
let wrapVersion = 1
/// The largest secret wrap takes, and the largest envelope unwrap reads: room
/// for the base64url of the largest secret and the other fields, so every
/// secret wrap accepts comes back through unwrap.
let maxSecret = 64 * 1024
let maxEnvelope = 128 * 1024

enum JvSeError: Error {
    case usage(String)
    case failure(String)
}

func writeStderr(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

func base64url(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// Public key as a JWK. Members are in lexicographic order (crv, kty, x, y),
/// which is also the RFC 7638 thumbprint input order.
func publicKeyJWK(_ publicKey: P256.Signing.PublicKey) -> String {
    let x963 = publicKey.x963Representation  // 0x04 || X (32) || Y (32)
    let x = x963.subdata(in: 1..<33)
    let y = x963.subdata(in: 33..<65)
    return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(base64url(x))\",\"y\":\"\(base64url(y))\"}"
}

/// Parses `--flag value` and bare `--flag` options. Unknown flags are a usage error.
func parseOptions(_ args: ArraySlice<String>, valueFlags: Set<String>, boolFlags: Set<String>) throws
    -> (values: [String: String], bools: Set<String>)
{
    var values: [String: String] = [:]
    var bools: Set<String> = []
    var index = args.startIndex
    while index < args.endIndex {
        let arg = args[index]
        if valueFlags.contains(arg) {
            let next = args.index(after: index)
            guard next < args.endIndex else { throw JvSeError.usage("\(arg) needs a value") }
            values[arg] = args[next]
            index = args.index(after: next)
        } else if boolFlags.contains(arg) {
            bools.insert(arg)
            index = args.index(after: index)
        } else {
            throw JvSeError.usage("unknown argument: \(arg)")
        }
    }
    return (values, bools)
}

func requireSecureEnclave() throws {
    guard SecureEnclave.isAvailable else { throw JvSeError.failure("Secure Enclave is not available") }
}

/// Writes the key blob with mode 0600, refusing to overwrite an existing file.
func writeKeyBlob(_ blob: Data, to path: String) throws {
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
    guard fd >= 0 else {
        throw JvSeError.failure("cannot create \(path): \(String(cString: strerror(errno)))")
    }
    defer { close(fd) }
    // open() honours the umask; make the mode explicit regardless.
    guard fchmod(fd, 0o600) == 0 else {
        throw JvSeError.failure("cannot chmod \(path): \(String(cString: strerror(errno)))")
    }
    let written = blob.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    guard written == blob.count else {
        throw JvSeError.failure("short write to \(path)")
    }
    try syncDurably(fd, path)
    let directory = (path as NSString).deletingLastPathComponent
    let dirFd = open(directory.isEmpty ? "." : directory, O_RDONLY)
    guard dirFd >= 0 else {
        throw JvSeError.failure("cannot open \(directory) to sync it: \(String(cString: strerror(errno)))")
    }
    defer { close(dirFd) }
    try syncDurably(dirFd, directory)
}

/// fsync hands the data to the drive, which may keep it in its cache;
/// F_FULLFSYNC asks the drive to write it out, so a key blob outlives a
/// power cut. fsync is the fall-back where a file system refuses it.
func syncDurably(_ fd: Int32, _ path: String) throws {
    if fcntl(fd, F_FULLFSYNC) == 0 { return }
    guard fsync(fd) == 0 else {
        throw JvSeError.failure("cannot sync \(path): \(String(cString: strerror(errno)))")
    }
}

func base64urlDecode(_ text: String) -> Data? {
    var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    guard !base64.contains("=") else { return nil }
    base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
    return Data(base64Encoded: base64)
}

func readKeyBlob(_ path: String) throws -> Data {
    guard let blob = FileManager.default.contents(atPath: path) else {
        throw JvSeError.failure("cannot read key blob \(path)")
    }
    return blob
}

func loadKey(_ path: String, context: LAContext? = nil) throws -> SecureEnclave.P256.Signing.PrivateKey {
    let blob = try readKeyBlob(path)
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
    } catch {
        throw JvSeError.failure("cannot load key from \(path): \(error)")
    }
}

func create(_ args: ArraySlice<String>) throws {
    let options = try parseOptions(args, valueFlags: ["--out"], boolFlags: ["--user-presence"])
    guard let out = options.values["--out"] else { throw JvSeError.usage("create needs --out <path>") }
    try requireSecureEnclave()

    // .privateKeyUsage alone: signing needs no user interaction, so a background
    // agent can sign. .userPresence adds Touch ID or password on every signature.
    // AfterFirstUnlockThisDeviceOnly: usable while the screen is locked once the
    // user has logged in since boot; ThisDeviceOnly is implied by the enclave anyway.
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if options.bools.contains("--user-presence") { flags.insert(.userPresence) }
    var cfError: Unmanaged<CFError>?
    guard
        let accessControl = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags, &cfError)
    else {
        let reason = cfError.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
        throw JvSeError.failure("cannot create access control: \(reason)")
    }

    let key: SecureEnclave.P256.Signing.PrivateKey
    do {
        key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: accessControl)
    } catch {
        throw JvSeError.failure("cannot create Secure Enclave key: \(error)")
    }
    try writeKeyBlob(key.dataRepresentation, to: out)
    print(publicKeyJWK(key.publicKey))
}

func pubkey(_ args: ArraySlice<String>) throws {
    let options = try parseOptions(args, valueFlags: ["--key"], boolFlags: [])
    guard let path = options.values["--key"] else { throw JvSeError.usage("pubkey needs --key <path>") }
    try requireSecureEnclave()
    print(publicKeyJWK(try loadKey(path).publicKey))
}

func sign(_ args: ArraySlice<String>) throws {
    let options = try parseOptions(args, valueFlags: ["--key"], boolFlags: ["--no-interaction"])
    guard let path = options.values["--key"] else { throw JvSeError.usage("sign needs --key <path>") }
    try requireSecureEnclave()

    // With --no-interaction a key that needs user presence fails fast instead of
    // waiting on an authentication prompt nobody can answer.
    let context = LAContext()
    context.localizedReason = "sign a Mehen request"
    if options.bools.contains("--no-interaction") { context.interactionNotAllowed = true }

    let key = try loadKey(path, context: context)
    let data = FileHandle.standardInput.readDataToEndOfFile()
    do {
        let signature = try key.signature(for: data)  // ECDSA over SHA-256(data)
        print(base64url(signature.rawRepresentation))  // r || s, 64 bytes
    } catch {
        throw JvSeError.failure("signing failed: \(error)")
    }
}

func readInput(_ what: String, limit: Int) throws -> Data {
    var data = Data()
    while data.count <= limit {
        let chunk: Data?
        do {
            chunk = try FileHandle.standardInput.read(upToCount: limit + 1 - data.count)
        } catch {
            throw JvSeError.failure("cannot read \(what) from stdin: \(error)")
        }
        guard let chunk, !chunk.isEmpty else { break }
        data.append(chunk)
    }
    guard data.count <= limit else { throw JvSeError.failure("\(what) on stdin is over \(limit) bytes") }
    guard !data.isEmpty else { throw JvSeError.failure("no \(what) on stdin") }
    return data
}

func agreementAccessControl() throws -> SecAccessControl {
    var cfError: Unmanaged<CFError>?
    guard
        let accessControl = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &cfError)
    else {
        let reason = cfError.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
        throw JvSeError.failure("cannot create access control: \(reason)")
    }
    return accessControl
}

/// Never prompts: a key-agreement key made here needs no user presence, and
/// one that did would fail rather than wait on a dialog nobody sees.
func loadAgreementKey(_ path: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    let blob = try readKeyBlob(path)
    let context = LAContext()
    context.interactionNotAllowed = true
    do {
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
    } catch {
        throw JvSeError.failure("cannot load key from \(path): \(error)")
    }
}

func loadOrCreateAgreementKey(_ path: String, create: Bool) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    if create && !FileManager.default.fileExists(atPath: path) {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: false, accessControl: try agreementAccessControl())
        } catch let error as JvSeError {
            throw error
        } catch {
            throw JvSeError.failure("cannot create Secure Enclave key: \(error)")
        }
        do {
            try writeKeyBlob(key.dataRepresentation, to: path)
            return key
        } catch {
            // Another wrap created it first: use that one.
            guard FileManager.default.fileExists(atPath: path) else { throw error }
        }
    }
    return try loadAgreementKey(path)
}

/// HKDF-SHA256 over the ECDH secret, bound to the version and to both public
/// keys, so an envelope opens only for the key it was sealed to.
func wrapKey(_ shared: SharedSecret, ephemeral: Data, recipient: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: Data(), sharedInfo: wrapInfo + ephemeral + recipient, outputByteCount: 32)
}

struct Envelope: Codable {
    let v: Int
    let epk: String
    let nonce: String
    let ct: String
    let tag: String
}

func wrap(_ args: ArraySlice<String>) throws {
    let options = try parseOptions(args, valueFlags: ["--key"], boolFlags: ["--create-if-missing"])
    guard let path = options.values["--key"] else { throw JvSeError.usage("wrap needs --key <path>") }
    try requireSecureEnclave()
    let secret = try readInput("secret", limit: maxSecret)
    let recipient = try loadOrCreateAgreementKey(path, create: options.bools.contains("--create-if-missing")).publicKey

    let ephemeral = P256.KeyAgreement.PrivateKey()
    let epk = ephemeral.publicKey.x963Representation
    let box: AES.GCM.SealedBox
    do {
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let key = wrapKey(shared, ephemeral: epk, recipient: recipient.x963Representation)
        box = try AES.GCM.seal(secret, using: key, nonce: AES.GCM.Nonce(), authenticating: wrapInfo)
    } catch {
        throw JvSeError.failure("wrapping failed: \(error)")
    }
    let envelope = Envelope(
        v: wrapVersion, epk: base64url(epk), nonce: base64url(Data(box.nonce)), ct: base64url(box.ciphertext),
        tag: base64url(box.tag))
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    guard let json = try? encoder.encode(envelope) else { throw JvSeError.failure("cannot encode the envelope") }
    FileHandle.standardOutput.write(json + Data("\n".utf8))
}

func unwrap(_ args: ArraySlice<String>) throws {
    let options = try parseOptions(args, valueFlags: ["--key"], boolFlags: [])
    guard let path = options.values["--key"] else { throw JvSeError.usage("unwrap needs --key <path>") }
    try requireSecureEnclave()
    let input = try readInput("envelope", limit: maxEnvelope)
    guard let envelope = try? JSONDecoder().decode(Envelope.self, from: input) else {
        throw JvSeError.failure("the envelope is not valid JSON of the expected shape")
    }
    guard envelope.v == wrapVersion else { throw JvSeError.failure("unsupported envelope version \(envelope.v)") }
    guard let epk = base64urlDecode(envelope.epk), let nonceBytes = base64urlDecode(envelope.nonce),
        let ciphertext = base64urlDecode(envelope.ct), let tag = base64urlDecode(envelope.tag),
        nonceBytes.count == 12, tag.count == 16
    else {
        throw JvSeError.failure("the envelope's fields are not base64url of the expected sizes")
    }
    let ephemeral: P256.KeyAgreement.PublicKey
    do {
        ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: epk)
    } catch {
        throw JvSeError.failure("the envelope's ephemeral key is not a P-256 point")
    }
    let key = try loadAgreementKey(path)
    let secret: Data
    do {
        let shared = try key.sharedSecretFromKeyAgreement(with: ephemeral)
        let symmetric = wrapKey(shared, ephemeral: epk, recipient: key.publicKey.x963Representation)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceBytes), ciphertext: ciphertext, tag: tag)
        secret = try AES.GCM.open(box, using: symmetric, authenticating: wrapInfo)
    } catch {
        throw JvSeError.failure("the envelope does not open with this key: it was changed, or sealed to another key")
    }
    FileHandle.standardOutput.write(secret)
}

func run(_ arguments: [String]) -> Int32 {
    guard arguments.count >= 2 else {
        writeStderr(usageText)
        return 2
    }
    let rest = arguments.dropFirst(2)
    do {
        switch arguments[1] {
        case "create": try create(rest)
        case "pubkey": try pubkey(rest)
        case "sign": try sign(rest)
        case "wrap": try wrap(rest)
        case "unwrap": try unwrap(rest)
        case "available":
            guard rest.isEmpty else { throw JvSeError.usage("available takes no arguments") }
            return SecureEnclave.isAvailable ? 0 : 1
        case "-h", "--help", "help":
            print(usageText)
        default:
            throw JvSeError.usage("unknown command: \(arguments[1])")
        }
        return 0
    } catch JvSeError.usage(let message) {
        writeStderr("mehen-se: \(message)\n\(usageText)")
        return 2
    } catch JvSeError.failure(let message) {
        writeStderr("mehen-se: \(message)")
        return 1
    } catch {
        writeStderr("mehen-se: \(error)")
        return 1
    }
}

exit(run(CommandLine.arguments))
