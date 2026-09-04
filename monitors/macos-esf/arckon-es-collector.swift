// RiskRaven Arckon — macOS Endpoint Security collector (native, real-time).
//
// Subscribes to kernel-level file-access + login events via Apple's
// Endpoint Security framework and streams them as NDJSON over a Unix
// domain socket to the Python agent (monitors/macos_esf.py).
//
// WHY NATIVE: The ES API is C/Swift-only — Python cannot call es_new_client().
// This is a small, auditable, signed binary that isolates privileged code.
// The Python agent needs NO entitlement (smaller attack surface).
//
// ENTITLEMENT: com.apple.developer.endpoint-security.client (approved for
// team SWRJ6ZV39K on 2026-07-10, request SMH99JLXP2).
//
// DEPLOYMENT: root LaunchDaemon (ES requires root + Full Disk Access),
// signed Developer ID + entitlement, hardened runtime, notarized.
// See build.sh and ai.mfdynamics.arckon-es-collector.plist.
//
// OUTPUT: one JSON object per line (NDJSON) over a Unix domain socket:
//   {"type":"file_access","timestamp":"...","process_name":"claude",
//    "process_path":"...","process_id":1234,"path":"/Users/.../secrets.pem",
//    "action":"read","signing_id":"com.anthropic.claude","team_id":"XYZ","uid":501}
//   {"type":"login","timestamp":"...","process_name":"sshd",
//    "process_id":5678,"action":"login","uid":0}

import EndpointSecurity
import Foundation
import Darwin

// The Python agent (consumer) binds; this daemon (root) connects.
let socketPath = ProcessInfo.processInfo.environment["ARCKON_ES_SOCKET"]
    ?? "/var/run/arckon-es-collector.sock"
let selfPid = getpid()

signal(SIGPIPE, SIG_IGN)  // ignore broken pipe — handle -1 from send()

// MARK: - NDJSON Unix-socket sink (lazy connect, bounded buffer, retry)

final class EventSink {
    private let path: String
    private var fd: Int32 = -1
    private let queue = DispatchQueue(label: "ai.mfdynamics.arckon.es.sink")
    private var buffer: [Data] = []
    private let maxBuffer = 5000

    init(path: String) { self.path = path }

    private func connectIfNeeded() {
        guard fd < 0 else { return }
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { return }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        _ = path.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
                    strncpy(dst, src, capacity - 1)
                }
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(s, $0, len)
            }
        }
        if r == 0 { fd = s } else { close(s) }
    }

    func emit(_ line: Data) {
        queue.async {
            self.buffer.append(line)
            if self.buffer.count > self.maxBuffer {
                let overflow = self.buffer.count - self.maxBuffer
                self.buffer.removeFirst(overflow)
            }
            self.flush()
        }
    }

    private func flush() {
        connectIfNeeded()
        guard fd >= 0 else { return }
        while let chunk = buffer.first {
            let n = chunk.withUnsafeBytes { p in
                Darwin.send(fd, p.baseAddress, p.count, 0)
            }
            if n < 0 { close(fd); fd = -1; return }
            buffer.removeFirst()
        }
    }
}

// MARK: - ES message field extraction

@inline(__always)
func tokenToString(_ t: es_string_token_t) -> String {
    guard t.length > 0, let d = t.data else { return "" }
    return String(decoding: UnsafeRawBufferPointer(start: d, count: t.length), as: UTF8.self)
}

let iso: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
}()

let sink = EventSink(path: socketPath)

// MARK: - File access event handler

func handleFileAccess(_ msg: UnsafePointer<es_message_t>, action: String) {
    let eventType = msg.pointee.event_type

    // Extract the file path from the event's target file
    var path = ""
    switch eventType {
    case ES_EVENT_TYPE_NOTIFY_OPEN:
        path = tokenToString(msg.pointee.event.open.file.pointee.path)
    case ES_EVENT_TYPE_NOTIFY_WRITE:
        path = tokenToString(msg.pointee.event.write.target.pointee.path)
    case ES_EVENT_TYPE_NOTIFY_RENAME:
        path = tokenToString(msg.pointee.event.rename.source.pointee.path)
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        path = tokenToString(msg.pointee.event.unlink.target.pointee.path)
    default:
        return
    }

    if path.isEmpty { return }

    // Get the process audit token for identity
    let proc = msg.pointee.process
    let atoken = proc.pointee.audit_token
    let pid = audit_token_to_pid(atoken)
    if pid == selfPid { return }

    let procPath = tokenToString(proc.pointee.executable.pointee.path)
    let procName = (procPath as NSString).lastPathComponent

    // Extract signing identity for anti-spoofing verification (direct fields
    // on es_process_t — not separate API functions)
    let signingId = tokenToString(proc.pointee.signing_id)
    let teamId = tokenToString(proc.pointee.team_id)
    let uid = audit_token_to_ruid(atoken)

    let obj: [String: Any] = [
        "type": "file_access",
        "timestamp": iso.string(from: Date()),
        "process_name": procName,
        "process_path": procPath,
        "process_id": Int(pid),
        "path": path,
        "action": action,
        "signing_id": signingId,
        "team_id": teamId,
        "uid": Int(uid),
    ]
    guard var data = try? JSONSerialization.data(withJSONObject: obj) else { return }
    data.append(0x0A)
    sink.emit(data)
}

// MARK: - Login event handler

func handleLogin(_ msg: UnsafePointer<es_message_t>) {
    let proc = msg.pointee.process
    let atoken = proc.pointee.audit_token
    let pid = audit_token_to_pid(atoken)
    if pid == selfPid { return }

    let procPath = tokenToString(proc.pointee.executable.pointee.path)
    let procName = (procPath as NSString).lastPathComponent
    let uid = audit_token_to_ruid(atoken)

    let obj: [String: Any] = [
        "type": "login",
        "timestamp": iso.string(from: Date()),
        "process_name": procName,
        "process_path": procPath,
        "process_id": Int(pid),
        "action": "login",
        "uid": Int(uid),
    ]
    guard var data = try? JSONSerialization.data(withJSONObject: obj) else { return }
    data.append(0x0A)
    sink.emit(data)
}

// MARK: - Client setup

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("arckon-es-collector: \(msg)\n".utf8))
    exit(1)
}

var client: OpaquePointer?

// es_new_client can fail with ERR_NOT_PERMITTED if Full Disk Access has not
// yet been granted. Rather than exit (which triggers launchd's crash-loop
// "penalty box" throttle and prevents auto-recovery once the user grants
// FDA), we sleep-and-retry indefinitely. This keeps the process alive so
// launchd's KeepAlive never kicks in, and the moment FDA is granted the
// next attempt succeeds. (ERR_NOT_ENTITLED is a build/signing error that
// cannot be fixed at runtime — fail fast there.)
while true {
    let newRes = es_new_client(&client) { _, msg in
        let eventType = msg.pointee.event_type
        switch eventType {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            handleFileAccess(msg, action: "open")
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            handleFileAccess(msg, action: "write")
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            handleFileAccess(msg, action: "rename")
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            handleFileAccess(msg, action: "unlink")
        case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
            handleLogin(msg)
        default:
            break
        }
    }

    switch newRes {
    case ES_NEW_CLIENT_RESULT_SUCCESS:
        break
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        fail("missing com.apple.developer.endpoint-security.client entitlement")
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        // Full Disk Access not granted yet. Sleep 30s and retry so the
        // process stays alive (no crash-loop) and auto-recovers once
        // the user grants FDA in System Settings.
        FileHandle.standardError.write(Data(
            "arckon-es-collector: waiting for Full Disk Access — retry in 30s\n".utf8))
        sleep(30)
        continue
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        fail("must run as root")
    default:
        FileHandle.standardError.write(Data(
            "arckon-es-collector: es_new_client failed (\(newRes.rawValue)) — retry in 30s\n".utf8))
        sleep(30)
        continue
    }
    break
}

guard let client else { fail("es_new_client returned nil client") }

// Subscribe to file-access + login events (NOTIFY = no deadline, can't stall)
var events: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_OPEN,
    ES_EVENT_TYPE_NOTIFY_WRITE,
    ES_EVENT_TYPE_NOTIFY_RENAME,
    ES_EVENT_TYPE_NOTIFY_UNLINK,
    ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
]

// ES API 3.0+ (macOS 13+) adds AUTHENTICATION events for richer login data
if #available(macOS 13.0, *) {
    events.append(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION)
}

if es_subscribe(client, &events, UInt32(events.count)) != ES_RETURN_SUCCESS {
    fail("es_subscribe failed")
}

FileHandle.standardError.write(Data(
    ("arckon-es-collector: subscribed to file-access + login events, "
     + "streaming to \(socketPath)\n").utf8))
dispatchMain()