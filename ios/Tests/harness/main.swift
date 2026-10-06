import Foundation
import Security

let legacyService = "cap_sec"
let currentService = "cap_sec_v2"
let upstreamService = "cap_sec_upstream"
let upstreamCurrentService = "cap_sec_upstream_v2"
let upstreamStandardService = "harness.standard.upstream"
let standardService = KeychainWrapper.standard.serviceName
// entitlements.plist uses a team prefix, an app-ID group, a shared group and a legacy group, as a typical app with an extension
// would: application-identifier <TEAM>.<bundle id> is the app-ID group the plugin uses as its app-private group, the first
// keychain-access-groups entry is the shared default group for writes without a group, and the second holds older copies.
let appIdGroup = "ABCDE12345.capacitor-secure-storage-plugin.harness"
let sharedGroup = appIdGroup + ".shared"
let olderGroup = appIdGroup + ".legacy"
let harnessBundle = "capacitor-secure-storage-plugin.harness"
let keyTag = Data("capacitor-secure-storage-plugin.v1".utf8)
let simKeyTag = Data("capacitor-secure-storage-plugin.v1.sim".utf8)
let magic = Data([0x00, 0x53, 0x4B, 0x01])
let marker = "better-capacitor-secure-storage-plugin"
var failures = 0

func check(_ name: String, _ condition: Bool, _ detail: String = "") {
    if !condition { failures += 1 }
    print("\(condition ? "PASS" : "FAIL") \(name)\(detail.isEmpty ? "" : " [\(detail)]")")
}

func makeVault(
    _ accessibility: SecureStorageVault.Accessibility = .whenUnlockedThisDeviceOnly,
    encrypts: Bool = true,
    deletes: Bool = false,
    currentName: String = currentService,
    legacyName: String = legacyService,
    standardName: String = standardService,
    keyTag: String = "capacitor-secure-storage-plugin.v1",
    bundleIdentifier: String? = harnessBundle,
    available: @escaping () -> Bool = { true }
) -> SecureStorageVault {
    return SecureStorageVault(
        configuration: SecureStorageVault.Configuration(accessibility: accessibility, encryptsValues: encrypts, deletesLegacyCopies: deletes),
        currentService: currentName,
        legacyService: legacyName,
        standardService: standardName,
        keyTag: keyTag,
        bundleIdentifier: bundleIdentifier,
        isProtectedDataAvailable: available
    )
}

func items(account: String? = nil, in itemService: String = currentService) -> [[String: Any]] {
    var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: itemService, kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true, kSecReturnData as String: true]
    if let account = account { query[kSecAttrAccount as String] = Data(account.utf8) }
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return status == errSecSuccess ? (result as? [[String: Any]] ?? []) : []
}

func accessible(_ account: String, in itemService: String = currentService) -> [String] {
    return items(account: account, in: itemService).map { $0[kSecAttrAccessible as String] as? String ?? "nil" }
}

func storedData(_ account: String, in itemService: String = currentService) -> [Data] {
    return items(account: account, in: itemService).compactMap { $0[kSecValueData as String] as? Data }
}

func groups(_ account: String, in itemService: String = currentService) -> [String] {
    return items(account: account, in: itemService).map { $0[kSecAttrAccessGroup as String] as? String ?? "nil" }.sorted()
}

func marked(_ account: String, in itemService: String = currentService) -> [Bool] {
    return items(account: account, in: itemService).map { ($0[kSecAttrLabel as String] as? String) == marker }
}

func encrypted(_ account: String, in itemService: String = currentService) -> Bool {
    let data = storedData(account, in: itemService)
    return !data.isEmpty && data.allSatisfy { $0.starts(with: magic) }
}

func copy(_ account: String, in group: String, service itemService: String = currentService) -> [String: Any]? {
    return items(account: account, in: itemService).first { ($0[kSecAttrAccessGroup as String] as? String) == group }
}

func modified(_ account: String, in group: String, service itemService: String = currentService) -> Date? {
    return copy(account, in: group, service: itemService)?[kSecAttrModificationDate as String] as? Date
}

func snapshot(_ itemService: String, account: String? = nil) -> [String] {
    return items(account: account, in: itemService).map { item in
        let name = (item[kSecAttrAccount as String] as? Data).map { String(decoding: $0, as: UTF8.self) } ?? "nil"
        let data = (item[kSecValueData as String] as? Data)?.base64EncodedString() ?? "nil"
        let date = (item[kSecAttrModificationDate as String] as? Date)?.timeIntervalSince1970 ?? 0
        return "\(name)|\(item[kSecAttrAccessGroup as String] ?? "nil")|\(item[kSecAttrAccessible as String] ?? "nil")|\(item[kSecAttrLabel as String] ?? "-")|\(data)|\(date)"
    }.sorted()
}

func legacySnapshot() -> [String] {
    return snapshot(legacyService) + snapshot(standardService)
}

func everything() -> [String] {
    return snapshot(currentService) + legacySnapshot()
}

func currentValue(_ vault: SecureStorageVault, _ account: String, in itemService: String = currentService) -> String {
    let data = storedData(account, in: itemService)
    guard data.count == 1 else { return "\(data.count) items" }
    return describe(vault.decodeValue(data[0]))
}

/// Adds an item with the SwiftKeychainWrapper shape directly, optionally in a given group.
func addRaw(_ account: String, _ data: Data, group: String?, accessibility: CFString = kSecAttrAccessibleAfterFirstUnlock, in itemService: String = legacyService, label: String? = nil) -> OSStatus {
    let encoded = Data(account.utf8)
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: itemService,
        kSecAttrAccount as String: encoded,
        kSecAttrGeneric as String: encoded,
        kSecAttrSynchronizable as String: false,
        kSecAttrAccessible as String: accessibility,
        kSecValueData as String: data,
    ]
    if let group = group { query[kSecAttrAccessGroup as String] = group }
    if let label = label { query[kSecAttrLabel as String] = label }
    return SecItemAdd(query as CFDictionary, nil)
}

func touch(_ account: String, in group: String, _ value: String) -> OSStatus {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: legacyService, kSecAttrAccount as String: Data(account.utf8), kSecAttrAccessGroup as String: group]
    return SecItemUpdate(query as CFDictionary, [kSecValueData as String: Data(value.utf8)] as CFDictionary)
}

func diagnostics(_ vault: SecureStorageVault) -> [String: Any] {
    return vault.queue.sync { vault.diagnostics() }
}

func counter(_ snapshot: [String: Any], _ name: String) -> Int {
    return snapshot[name] as? Int ?? -1
}

func delta(_ before: [String: Any], _ after: [String: Any], _ name: String) -> Int {
    return counter(after, name) - counter(before, name)
}

func listed(_ vault: SecureStorageVault) -> [String]? {
    guard case .resolve(let data) = vault.listStoredKeys(), let keys = data["value"] as? [String] else { return nil }
    return keys.sorted()
}

/// Fires ticks by hand on the vault queue.
final class HarnessTicker: SecureStorageTicker {
    private let lock = NSLock()
    private var handler: (() -> Void)?
    private var queue: DispatchQueue?
    func start(on queue: DispatchQueue, handler: @escaping () -> Void) { lock.lock(); self.queue = queue; self.handler = handler; lock.unlock() }
    func stop() { lock.lock(); handler = nil; lock.unlock() }
    func fire(times: Int = 1) {
        for _ in 0..<times {
            lock.lock(); let tick = handler; let target = queue; lock.unlock()
            if let tick = tick, let target = target { target.sync(execute: tick) }
        }
    }
}

let otherService = "harness.other"
let noServiceAccount = "__aio_key"

func noServiceItemExists() -> Bool {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: noServiceAccount, kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return false }
    return (result as? [[String: Any]] ?? []).contains { $0[kSecAttrService as String] == nil || ($0[kSecAttrService as String] as? String) == "" }
}

func keyAttributes(_ tag: Data) -> [[String: Any]] {
    let query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag, kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return status == errSecSuccess ? (result as? [[String: Any]] ?? []) : []
}

func keyCount(_ tag: Data) -> Int {
    return keyAttributes(tag).count
}

func deleteKeys() {
    SecItemDelete([kSecClass as String: kSecClassKey] as CFDictionary)
}

func allKeyCount() -> Int {
    let query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return status == errSecSuccess ? (result as? [[String: Any]] ?? []).count : 0
}

func tags(_ name: String) -> (name: String, secureEnclave: Data, software: Data) {
    return (name, Data(name.utf8), Data((name + ".sim").utf8))
}

func deleteService(_ itemService: String) {
    SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: itemService] as CFDictionary)
    SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: itemService, kSecAttrAccessGroup as String: appIdGroup] as CFDictionary)
}

func cleanAll() {
    for itemService in [currentService, legacyService, upstreamService, upstreamCurrentService, upstreamStandardService, standardService, otherService] { deleteService(itemService) }
    SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: noServiceAccount] as CFDictionary)
    deleteKeys()
}

func describe(_ outcome: SecureStorageVault.Outcome) -> String {
    switch outcome {
    case .resolve(let data): return "resolve \(data["value"].map { "\($0)" } ?? "-")"
    case .reject(let message, _): return "reject \(message)"
    case .locked: return "locked"
    }
}

func code(_ outcome: SecureStorageVault.Outcome) -> String {
    if case .reject(_, let code) = outcome { return code.rawValue }
    return "-"
}

func describe(_ result: SecureStorageVault.DecodeResult) -> String {
    switch result {
    case .plaintext(let s): return "plaintext(\(s))"
    case .decrypted(let s): return "decrypted(\(s))"
    case .locked: return "locked"
    case .invalid: return "invalid"
    }
}

func osStatusError(_ code: OSStatus) -> Unmanaged<CFError> {
    return Unmanaged.passRetained(CFErrorCreate(nil, kCFErrorDomainOSStatus, CFIndex(code), nil)!)
}

/// Wraps the real decryption and records the code of every failure.
func recordingDecryption(_ codes: @escaping (Int) -> Void) -> (SecKey, SecKeyAlgorithm, CFData, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? {
    return { key, algorithm, ciphertext, error in
        let result = SecKeyCreateDecryptedData(key, algorithm, ciphertext, error)
        if result == nil, let failure = error?.pointee {
            codes(CFErrorGetCode(failure.takeUnretainedValue()))
        }
        return result
    }
}

func readData(_ vault: SecureStorageVault, _ key: String) -> Data? {
    let read = vault.current.readItem(key)
    return read.status == errSecSuccess ? read.data : nil
}

func encode(_ vault: SecureStorageVault, _ value: String) -> Data? {
    if case .encoded(let data) = vault.encodeValue(value) { return data }
    return nil
}

func write(_ vault: SecureStorageVault, _ key: String, _ data: Data, _ accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) -> OSStatus {
    return vault.current.writeItem(key, data: data, accessibility: accessibility, accessGroup: appIdGroup)
}

func settle(_ vault: SecureStorageVault) {
    vault.queue.sync {}
    vault.queue.sync {}
}

final class EventLog {
    private let lock = NSLock()
    private var storage: [String] = []
    var events: [String] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
    func record(_ event: String) { lock.lock(); storage.append(event); lock.unlock() }
    func reset() { lock.lock(); storage = []; lock.unlock() }
}

final class Flag {
    private let lock = NSLock()
    private var storage: Bool
    init(_ value: Bool) { storage = value }
    func read() -> Bool { lock.lock(); defer { lock.unlock() }; return storage }
    func write(_ value: Bool) { lock.lock(); storage = value; lock.unlock() }
}

final class Tally {
    private let lock = NSLock()
    private var storage = 0
    func add() { lock.lock(); storage += 1; lock.unlock() }
    func read() -> Int { lock.lock(); defer { lock.unlock() }; return storage }
}

let wrapper = KeychainWrapper(serviceName: legacyService)
let wrapperAppGroup = KeychainWrapper(serviceName: legacyService, accessGroup: appIdGroup)
let wrapperOlderGroup = KeychainWrapper(serviceName: legacyService, accessGroup: olderGroup)
let wrapperCurrent = KeychainWrapper(serviceName: currentService)
let wrapperUpstream = KeychainWrapper(serviceName: upstreamService)
let wrapperUpstreamStandard = KeychainWrapper(serviceName: upstreamStandardService)
let phaseTwo = SecureStorageVault.Configuration(deletesLegacyCopies: true)

cleanAll()
let vault = makeVault()
let plainVault = makeVault(.afterFirstUnlock, encrypts: false)
let plainStrictVault = makeVault(.whenUnlockedThisDeviceOnly, encrypts: false)

check("0 the default vault uses cap_sec_v2, cap_sec and the bundle id service and keeps older copies", SecureStorageVault().current.service == currentService && SecureStorageVault().legacy.service == legacyService && SecureStorageVault().standard.service == standardService && !SecureStorageVault().configuration.deletesLegacyCopies)

vault.queue.sync {
    print("--- 1 encrypted round trip")
    let encoded = encode(vault, "__secured_1234")
    check("1 encodeValue produces MAGIC prefix", encoded?.starts(with: magic) == true)
    check("1 writeItem fresh", encoded.map { write(vault, "t1", $0) } == errSecSuccess)
    let stored = readData(vault, "t1")
    check("1 stored data starts with MAGIC", stored?.starts(with: magic) == true)
    check("1 stored data is not plaintext", stored.map { !String(decoding: $0, as: UTF8.self).contains("1234") } == true)
    check("1 decodeValue decrypted", stored.map { describe(vault.decodeValue($0)) } == "decrypted(__secured_1234)")
    check("1 accessible aku", accessible("t1") == ["aku"], "\(accessible("t1"))")
    check("1 storeValue/loadValue outcome", describe(vault.storeValue("__secured_x", forKey: "t1b")) == "resolve true" && describe(vault.loadValue(forKey: "t1b")) == "resolve __secured_x")
    check("1 storeValue overwrites encrypted", describe(vault.storeValue("__secured_y", forKey: "t1b")) == "resolve true" && describe(vault.loadValue(forKey: "t1b")) == "resolve __secured_y")
    check("1 storeValue class is the configured default", accessible("t1b") == ["aku"], "\(accessible("t1b"))")
    check("1 storeValue writes one labelled cap_sec_v2 item in the app-ID group and nothing into cap_sec", groups("t1b") == [appIdGroup] && marked("t1b") == [true] && items(in: legacyService).isEmpty, "\(groups("t1b"))")
}
check("1 the cap_sec_v2 item has the SwiftKeychainWrapper shape", wrapperCurrent.hasValue(forKey: "t1b"))

print("--- 2 a 0.13.0 item in the default group")
check("2 seed 0.13.0 item with afterFirstUnlock", wrapper.set("__secured_1234", forKey: "pin", withAccessibility: .afterFirstUnlock))
check("2 seeded class ck in cap_sec", accessible("pin", in: legacyService) == ["ck"])
let pinLegacy = snapshot(legacyService, account: "pin")
vault.queue.sync {
    check("2 cap_sec_v2 empty before", items(account: "pin").isEmpty)
    check("2 get returns the 0.13.0 value", describe(vault.loadValue(forKey: "pin")) == "resolve __secured_1234")
    check("2 the value now sits in cap_sec_v2: app-ID group, aku, encrypted, labelled", groups("pin") == [appIdGroup] && accessible("pin") == ["aku"] && encrypted("pin") && marked("pin") == [true], "\(groups("pin")) \(accessible("pin"))")
    check("2 the cap_sec_v2 item decodes to the value", currentValue(vault, "pin") == "decrypted(__secured_1234)")
}
check("2 the 0.13.0 item is unchanged", pinLegacy.count == 1 && snapshot(legacyService, account: "pin") == pinLegacy)
check("2 the 0.13.0 wrapper still reads its value", wrapper.string(forKey: "pin") == "__secured_1234")
let pinCurrent = snapshot(currentService, account: "pin")
vault.queue.sync {
    check("2 the next get reads cap_sec_v2 and writes nothing", describe(vault.loadValue(forKey: "pin")) == "resolve __secured_1234" && snapshot(currentService, account: "pin") == pinCurrent)
}
check("2b seed 0.13.0 pin3", wrapper.set("__secured_old", forKey: "pin3", withAccessibility: .afterFirstUnlock))
vault.queue.sync {
    check("2b set over a 0.13.0 item writes cap_sec_v2", describe(vault.storeValue("__secured_new", forKey: "pin3")) == "resolve true" && accessible("pin3") == ["aku"] && describe(vault.loadValue(forKey: "pin3")) == "resolve __secured_new")
}
check("2b the 0.13.0 item keeps its value and class", wrapper.string(forKey: "pin3") == "__secured_old" && accessible("pin3", in: legacyService) == ["ck"])

print("--- 2c get without encryption copies plaintext with a tightened class")
check("2c seed 0.13.0 pin4", wrapper.set("__secured_p4", forKey: "pin4", withAccessibility: .afterFirstUnlock))
plainStrictVault.queue.sync {
    check("2c get resolves", describe(plainStrictVault.loadValue(forKey: "pin4")) == "resolve __secured_p4")
    check("2c cap_sec_v2 holds plaintext with aku", accessible("pin4") == ["aku"] && storedData("pin4") == [Data("__secured_p4".utf8)], "\(accessible("pin4"))")
}
check("2c the 0.13.0 item stays ck", accessible("pin4", in: legacyService) == ["ck"] && storedData("pin4", in: legacyService) == [Data("__secured_p4".utf8)])

print("--- 3 copies in two access groups")
check("3 seed app-ID group", wrapperAppGroup.set("__secured_sig", forKey: "sig", withAccessibility: .afterFirstUnlock))
check("3 seed default group duplicate", wrapper.set("__secured_sig", forKey: "sig", withAccessibility: .afterFirstUnlock))
check("3 two cap_sec items in two groups", groups("sig", in: legacyService) == [appIdGroup, sharedGroup], "\(groups("sig", in: legacyService))")
let sigLegacy = snapshot(legacyService, account: "sig")
vault.queue.sync {
    let keysBefore = vault.legacy.listKeys().keys
    check("3 listKeys dedupes", keysBefore.filter { $0 == "sig" }.count == 1, "\(keysBefore)")
    check("3 get resolves", describe(vault.loadValue(forKey: "sig")) == "resolve __secured_sig")
    check("3 one encrypted cap_sec_v2 item", groups("sig") == [appIdGroup] && encrypted("sig"), "\(groups("sig"))")
}
check("3 both cap_sec copies unchanged", snapshot(legacyService, account: "sig") == sigLegacy)
check("3b seed dev in two groups", wrapperAppGroup.set("__secured_dev", forKey: "dev", withAccessibility: .afterFirstUnlock) && wrapper.set("__secured_dev", forKey: "dev", withAccessibility: .afterFirstUnlock))
let devLegacy = snapshot(legacyService, account: "dev")
vault.queue.sync {
    check("3b sweep resolves", describe(vault.migrateLegacyValues()) == "resolve -")
    check("3b sweep wrote one encrypted aku cap_sec_v2 item", groups("dev") == [appIdGroup] && accessible("dev") == ["aku"] && encrypted("dev"))
    check("3b both cap_sec copies unchanged", devLegacy.count == 2 && snapshot(legacyService, account: "dev") == devLegacy)
    check("3b remove deletes the cap_sec_v2 item and both cap_sec copies", describe(vault.removeValue(forKey: "dev")) == "resolve true" && items(account: "dev").isEmpty && items(account: "dev", in: legacyService).isEmpty)
}
plainStrictVault.queue.sync {
    check("3c seed plaintext in two groups", wrapperAppGroup.set("__secured_grp", forKey: "grp", withAccessibility: .afterFirstUnlock) && wrapper.set("__secured_grp", forKey: "grp", withAccessibility: .afterFirstUnlock))
    let grpLegacy = snapshot(legacyService, account: "grp")
    check("3c sweep resolves", describe(plainStrictVault.migrateLegacyValues()) == "resolve -")
    check("3c sweep without encryption copies plaintext with aku", groups("grp") == [appIdGroup] && accessible("grp") == ["aku"] && storedData("grp") == [Data("__secured_grp".utf8)], "\(accessible("grp"))")
    check("3c both cap_sec copies unchanged", snapshot(legacyService, account: "grp") == grpLegacy)
}

vault.queue.sync {
    print("--- 4 keys, remove and clear")
    deleteService(currentService)
    deleteService(legacyService)
    for key in ["a", "b", "c"] { _ = vault.storeValue("__secured_\(key)", forKey: key) }
    let listedKeys = vault.current.listKeys().keys
    check("4 listKeys exactly a,b,c", listedKeys.sorted() == ["a", "b", "c"], "\(listedKeys)")
    check("4 keys outcome", listed(vault) == ["a", "b", "c"])
    check("4 remove missing rejects", describe(vault.removeValue(forKey: "zzz")) == "reject Item with given key does not exist")
    check("4 remove existing", describe(vault.removeValue(forKey: "a")) == "resolve true")
    check("4 get removed rejects missing", describe(vault.loadValue(forKey: "a")) == "reject Item with given key does not exist")
    check("4 deleteAll", vault.current.deleteAll() == errSecSuccess)
    let emptyList = vault.current.listKeys()
    check("4 listKeys empty after deleteAll", emptyList.status == errSecSuccess && emptyList.keys.isEmpty)
    check("4 deleteAll on empty returns notFound", vault.current.deleteAll() == errSecItemNotFound)
    _ = vault.storeValue("__secured_c", forKey: "c")
    KeychainWrapper.standard.set("__secured_std", forKey: "c")
    KeychainWrapper.standard.set("__secured_only", forKey: "stdOnly")
    check("4 seed a cap_sec item that was never read and its bundle id copy", wrapper.set("__secured_l", forKey: "l", withAccessibility: .afterFirstUnlock) && KeychainWrapper.standard.set("__secured_l_std", forKey: "l"))
    check("4 keys lists cap_sec_v2 and cap_sec keys", listed(vault) == ["c", "l"])
    check("4 clear resolves true", describe(vault.removeAllValues()) == "resolve true")
    check("4 clear removed cap_sec_v2, cap_sec and the bundle id copies of their keys", items().isEmpty && items(in: legacyService).isEmpty && !KeychainWrapper.standard.hasValue(forKey: "c") && !KeychainWrapper.standard.hasValue(forKey: "l"))
    check("4 clear keeps bundle id items of other keys", KeychainWrapper.standard.string(forKey: "stdOnly") == "__secured_only")
    check("4 remove deletes a bundle id only key", describe(vault.removeValue(forKey: "stdOnly")) == "resolve true" && !KeychainWrapper.standard.hasValue(forKey: "stdOnly"))
    check("4 clear on empty store resolves", describe(vault.removeAllValues()) == "resolve true")
    check("4 SE key survives clear", keyCount(keyTag) + keyCount(simKeyTag) == 1)
}

vault.queue.sync {
    print("--- 5 invalid ciphertext")
    let garbage = magic + Data((0..<80).map { UInt8(truncatingIfNeeded: $0 &* 37) })
    check("5 write garbage", write(vault, "bad", garbage) == errSecSuccess)
    var garbageCodes: [Int] = []
    vault.decryptCiphertext = recordingDecryption { garbageCodes.append($0) }
    let retriesBefore = vault.counters.decryptRetries
    check("5 decodeValue invalid (not locked)", describe(vault.decodeValue(garbage)) == "invalid")
    check("5 garbage fails with errSecParam or errSecDecode on each of three attempts", garbageCodes.count == 3 && garbageCodes.allSatisfy { $0 == Int(errSecParam) || $0 == Int(errSecDecode) } && vault.counters.decryptRetries - retriesBefore == 2, "\(garbageCodes)")
    vault.decryptCiphertext = SecKeyCreateDecryptedData
    let badRead = vault.loadValue(forKey: "bad")
    check("5 loadValue reports undecryptable as missing with code UNREADABLE", describe(badRead) == "reject Item with given key does not exist" && code(badRead) == "UNREADABLE", "\(describe(badRead)) \(code(badRead))")
    check("5 item still exists", items(account: "bad").count == 1)
    check("5 missing key has code NOT_FOUND", code(vault.loadValue(forKey: "never-written")) == "NOT_FOUND")
    let lockedVault = makeVault(available: { false })
    check("5 garbage decrypt while protected data unavailable is locked", describe(lockedVault.decodeValue(garbage)) == "locked")
    check("5 garbage decrypt while available is invalid", describe(vault.decodeValue(garbage)) == "invalid")
    check("5 short MAGIC-only data invalid", describe(vault.decodeValue(magic)) == "invalid")
    check("5 non-UTF-8 legacy standard value is missing + UNREADABLE", KeychainWrapper.standard.set(Data([0xFF, 0xFE, 0x00]), forKey: "badStd") && describe(vault.loadValue(forKey: "badStd")) == "reject Item with given key does not exist" && code(vault.loadValue(forKey: "badStd")) == "UNREADABLE")
    check("5 the unreadable bundle id value is not copied", items(account: "badStd").isEmpty)
    check("5 non-UTF-8 plaintext in cap_sec_v2 is missing + UNREADABLE", write(vault, "badPlain", Data([0xFF, 0xFE, 0x00])) == errSecSuccess && describe(vault.loadValue(forKey: "badPlain")) == "reject Item with given key does not exist" && code(vault.loadValue(forKey: "badPlain")) == "UNREADABLE")
    check("5 seed a readable 0.13.0 copy next to the undecryptable cap_sec_v2 item", wrapper.set("__secured_older", forKey: "bad", withAccessibility: .afterFirstUnlock))
    check("5 an undecryptable cap_sec_v2 item never falls back to cap_sec", code(vault.loadValue(forKey: "bad")) == "UNREADABLE" && wrapper.string(forKey: "bad") == "__secured_older")
    check("5 set overwrites the undecryptable item", describe(vault.storeValue("__secured_fixed", forKey: "bad")) == "resolve true" && describe(vault.loadValue(forKey: "bad")) == "resolve __secured_fixed" && items(account: "bad").count == 1)
    _ = KeychainWrapper.standard.removeObject(forKey: "badStd")
    _ = wrapper.removeObject(forKey: "bad")
    _ = vault.current.deleteItem("bad")
    _ = vault.current.deleteItem("badPlain")
}

print("--- 6 concurrent first use on one vault")
let sixTags = tags("harness.6")
let concurrentVault = makeVault(keyTag: sixTags.name)
let group = DispatchGroup()
var concurrentResults: [Bool] = []
let resultsLock = NSLock()
for index in 0..<8 {
    group.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        concurrentVault.queue.async {
            let ok = encode(concurrentVault, "v\(index)") != nil
            resultsLock.lock(); concurrentResults.append(ok); resultsLock.unlock()
            group.leave()
        }
    }
}
group.wait()
check("6 all 8 encodes succeeded", concurrentResults.count == 8 && concurrentResults.allSatisfy { $0 })
check("6 exactly one key under tag", keyCount(sixTags.secureEnclave) + keyCount(sixTags.software) == 1, "se=\(keyCount(sixTags.secureEnclave)) sim=\(keyCount(sixTags.software))")
check("6 key is Secure Enclave", keyCount(sixTags.secureEnclave) == 1)
concurrentVault.queue.sync {
    let encoded = encode(concurrentVault, "__secured_cross")
    let other = makeVault(.afterFirstUnlock, keyTag: sixTags.name)
    check("6 second vault instance decrypts with same key", encoded.map { describe(other.decodeValue($0)) } == "decrypted(__secured_cross)")
    let plaintextReader = makeVault(.afterFirstUnlock, encrypts: false, keyTag: sixTags.name)
    check("6 vault with encryption off still decrypts", encoded.map { describe(plaintextReader.decodeValue($0)) } == "decrypted(__secured_cross)")
}

print("--- 7 key reuse")
func keyLabel(_ tag: Data) -> Data? {
    return keyAttributes(tag).first?[kSecAttrApplicationLabel as String] as? Data
}
func seedKey(tag: Data, secureEnclave: Bool) -> Bool {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error) else { return false }
    var attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: tag, kSecAttrAccessControl as String: access] as [String: Any],
    ]
    if secureEnclave { attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave }
    return SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil
}
for secureEnclave in [true, false] {
    let reuseTags = tags(secureEnclave ? "harness.7b" : "harness.7c")
    let tag = secureEnclave ? reuseTags.secureEnclave : reuseTags.software
    let label = secureEnclave ? "7b pre-existing SE key" : "7c pre-existing simulator software key (.sim tag)"
    check("\(label) seeded", seedKey(tag: tag, secureEnclave: secureEnclave) && keyCount(tag) == 1)
    let before = keyLabel(tag)
    let reuseVault = makeVault(keyTag: reuseTags.name)
    reuseVault.queue.sync {
        let result = encode(reuseVault, "__secured_reuse").map { describe(reuseVault.decodeValue($0)) } ?? "encode failed"
        check("\(label) found by lookup, round trip works", result == "decrypted(__secured_reuse)", result)
        check("\(label) reused, no new key created", keyLabel(tag) == before && keyCount(reuseTags.secureEnclave) + keyCount(reuseTags.software) == 1, "se=\(keyCount(reuseTags.secureEnclave)) sim=\(keyCount(reuseTags.software))")
    }
}
vault.queue.sync {
    check("7 garbage is invalid not locked", describe(vault.decodeValue(magic + Data(repeating: 7, count: 120))) == "invalid")
}
let freshTags = tags("harness.7f")
let freshKeyVault = makeVault(keyTag: freshTags.name)
freshKeyVault.queue.sync {
    check("7 fresh key round trip", encode(freshKeyVault, "__secured_fresh").map { describe(freshKeyVault.decodeValue($0)) } == "decrypted(__secured_fresh)")
    check("7 fresh key created under its tag", keyCount(freshTags.secureEnclave) == 1)
}

print("--- 10 protected data unavailable parks without running")
let protectedFlag = Flag(false)
let lockVault = makeVault(available: { protectedFlag.read() })
let log = EventLog()
var lockRuns: [String] = []
protectedFlag.write(true)
lockVault.queue.sync {
    check("10 seed old value", describe(lockVault.storeValue("__secured_old", forKey: "fifo")) == "resolve true")
}
protectedFlag.write(false)
lockVault.submitOperation(named: "get", key: "fifo", run: { lockRuns.append("get"); return lockVault.loadValue(forKey: "fifo") }, completion: { log.record("get \(describe($0))") })
lockVault.queue.sync {}
check("10 get parks without running, no callback", lockRuns.isEmpty && log.events.isEmpty, "\(lockRuns) \(log.events)")
lockVault.submitOperation(named: "set", key: "fifo", run: { lockRuns.append("set"); return lockVault.storeValue("__secured_new", forKey: "fifo") }, completion: { log.record("set \(describe($0))") })
lockVault.queue.sync {}
check("10 set parks behind get without running", lockRuns.isEmpty && log.events.isEmpty, "\(lockRuns) \(log.events)")
lockVault.queue.sync {
    check("10 stored value untouched while parked", readData(lockVault, "fifo").map { describe(lockVault.decodeValue($0)) } == "decrypted(__secured_old)")
}
protectedFlag.write(true)
lockVault.drainParkedOperations()
lockVault.queue.sync {}
check("10 drain runs get then set", lockRuns == ["get", "set"], "\(lockRuns)")
check("10 get resolves before set completes, with the pre-set value", log.events == ["get resolve __secured_old", "set resolve true"], "\(log.events)")
lockVault.queue.sync {
    check("10 set applied after drain", describe(lockVault.loadValue(forKey: "fifo")) == "resolve __secured_new")
}

print("--- 11 new op does not overtake a parked one")
log.reset()
lockRuns = []
protectedFlag.write(false)
lockVault.submitOperation(named: "A", key: "fifo", run: { lockRuns.append("A"); return lockVault.storeValue("__secured_A", forKey: "fifo") }, completion: { log.record("A \(describe($0))") })
lockVault.queue.sync {}
check("11 A parked while locked", lockRuns.isEmpty && log.events.isEmpty)
protectedFlag.write(true)
lockVault.submitOperation(named: "B", key: "fifo", run: { lockRuns.append("B"); return lockVault.loadValue(forKey: "fifo") }, completion: { log.record("B \(describe($0))") })
lockVault.drainParkedOperations()
lockVault.queue.sync {}
check("11 FIFO: A completes before B and B reads A's write", lockRuns == ["A", "B"] && log.events == ["A resolve true", "B resolve __secured_A"], "\(lockRuns) \(log.events)")
lockVault.drainParkedOperations()
lockVault.queue.sync {}
check("11 completed once", log.events.count == 2)

print("--- 13 parked 0.13.0 get + set: the set wins")
log.reset()
lockVault.queue.sync { _ = lockVault.current.deleteItem("fifo2") }
check("13 seed 0.13.0 plaintext", wrapper.set("__secured_legacy", forKey: "fifo2", withAccessibility: .afterFirstUnlock))
protectedFlag.write(false)
lockVault.submitOperation(named: "get", key: "fifo2", run: { lockVault.loadValue(forKey: "fifo2") }, completion: { log.record("get \(describe($0))") })
lockVault.submitOperation(named: "set", key: "fifo2", run: { lockVault.storeValue("__secured_fresh", forKey: "fifo2") }, completion: { log.record("set \(describe($0))") })
lockVault.queue.sync {}
protectedFlag.write(true)
lockVault.drainParkedOperations()
settle(lockVault)
check("13 get resolved the 0.13.0 value, then set", log.events == ["get resolve __secured_legacy", "set resolve true"], "\(log.events)")
lockVault.queue.sync {
    check("13 final value is the set value, encrypted aku", accessible("fifo2") == ["aku"] && describe(lockVault.loadValue(forKey: "fifo2")) == "resolve __secured_fresh")
}
check("13 the 0.13.0 item keeps the value it had", wrapper.string(forKey: "fifo2") == "__secured_legacy")

print("--- 14 key is never deleted")
let keepTags = tags("harness.14")
let keyVault = makeVault(keyTag: keepTags.name)
var labelBefore: Data?
keyVault.queue.sync {
    let before = encode(keyVault, "__secured_keep")
    labelBefore = keyLabel(keepTags.secureEnclave)
    let garbage = magic + Data(repeating: 9, count: 97)
    check("14 SE key present before", labelBefore != nil && keyCount(keepTags.secureEnclave) == 1)
    check("14 repeated garbage decrypts are invalid", (0..<5).map { _ in describe(keyVault.decodeValue(garbage)) }.allSatisfy { $0 == "invalid" })
    check("14 SE key still exists under the tag, unchanged", keyCount(keepTags.secureEnclave) == 1 && keyLabel(keepTags.secureEnclave) == labelBefore)
    check("14 earlier ciphertext still decrypts", before.map { describe(keyVault.decodeValue($0)) } == "decrypted(__secured_keep)")
    check("14 set/get round trip after failures", describe(keyVault.storeValue("__secured_after", forKey: "keep")) == "resolve true" && describe(keyVault.loadValue(forKey: "keep")) == "resolve __secured_after")
    check("14 clear keeps the key", describe(keyVault.removeAllValues()) == "resolve true" && keyLabel(keepTags.secureEnclave) == labelBefore)
}
let otherKeyVault = makeVault(keyTag: keepTags.name)
otherKeyVault.queue.sync {
    check("14 fresh instance finds the same key", describe(otherKeyVault.storeValue("__secured_again", forKey: "keep")) == "resolve true" && describe(otherKeyVault.loadValue(forKey: "keep")) == "resolve __secured_again" && keyLabel(keepTags.secureEnclave) == labelBefore && keyCount(keepTags.secureEnclave) + keyCount(keepTags.software) == 1)
}

print("--- 15 per-call accessibility override")
cleanAll()
vault.queue.sync {
    check("15 encrypted override lands on the item", describe(vault.storeValue("__secured_o1", forKey: "o1", accessibility: .afterFirstUnlockThisDeviceOnly)) == "resolve true" && accessible("o1") == ["cku"] && storedData("o1").first?.starts(with: magic) == true, "\(accessible("o1"))")
    check("15 override value reads back", describe(vault.loadValue(forKey: "o1")) == "resolve __secured_o1")
    check("15 override changes the class of an existing item", describe(vault.storeValue("__secured_o1b", forKey: "o1", accessibility: .whenUnlocked)) == "resolve true" && accessible("o1") == ["ak"], "\(accessible("o1"))")
    check("15 write without override returns to the default class", describe(vault.storeValue("__secured_o1c", forKey: "o1")) == "resolve true" && accessible("o1") == ["aku"], "\(accessible("o1"))")
    check("15 resolved per-call value is used", vault.resolveAccessibility("afterFirstUnlock").map { describe(vault.storeValue("__secured_o2", forKey: "o2", accessibility: $0)) } == "resolve true" && accessible("o2") == ["ck"], "\(accessible("o2"))")
    check("15 missing per-call value resolves to the default", vault.resolveAccessibility(nil).map { describe(vault.storeValue("__secured_o3", forKey: "o3", accessibility: $0)) } == "resolve true" && accessible("o3") == ["aku"], "\(accessible("o3"))")
    check("15 unsupported per-call value does not resolve", vault.resolveAccessibility("always") == nil)
}
plainVault.queue.sync {
    check("15 plaintext override lands on the item", describe(plainVault.storeValue("__secured_o4", forKey: "o4", accessibility: .whenUnlockedThisDeviceOnly)) == "resolve true" && accessible("o4") == ["aku"] && storedData("o4") == [Data("__secured_o4".utf8)], "\(accessible("o4"))")
}

print("--- 16 configured default class applied")
cleanAll()
let expectedClasses: [(SecureStorageVault.Accessibility, String)] = [
    (.whenUnlocked, "ak"),
    (.whenUnlockedThisDeviceOnly, "aku"),
    (.afterFirstUnlock, "ck"),
    (.afterFirstUnlockThisDeviceOnly, "cku"),
    (.whenPasscodeSetThisDeviceOnly, "akpu"),
]
for (accessibility, expected) in expectedClasses {
    for encrypts in [false, true] {
        let classVault = makeVault(accessibility, encrypts: encrypts)
        let key = "class.\(accessibility.rawValue).\(encrypts)"
        classVault.queue.sync {
            let outcome = describe(classVault.storeValue("__secured_class", forKey: key))
            check("16 \(accessibility.rawValue) encrypts \(encrypts) stores class \(expected)", outcome == "resolve true" && accessible(key) == [expected], "\(outcome) \(accessible(key))")
            check("16 \(accessibility.rawValue) encrypts \(encrypts) reads back", describe(classVault.loadValue(forKey: key)) == "resolve __secured_class")
        }
    }
}

print("--- 17 sweep")
cleanAll()
check("17a seed 0.13.0 s1", wrapper.set("__secured_s1", forKey: "s1", withAccessibility: .afterFirstUnlock))
check("17a seed bundle id duplicate of s1", KeychainWrapper.standard.set("__secured_stale", forKey: "s1"))
check("17a seed bundle id only s3", KeychainWrapper.standard.set("__secured_s3", forKey: "s3"))
let legacyBefore17 = legacySnapshot()
var s2Before: [Data] = []
vault.queue.sync {
    check("17a seed s2 with a per-call ck class", describe(vault.storeValue("__secured_s2", forKey: "s2", accessibility: .afterFirstUnlock)) == "resolve true")
    s2Before = storedData("s2")
    check("17a sweep resolves", describe(vault.migrateLegacyValues()) == "resolve -")
    check("17a s1 copied into cap_sec_v2, encrypted with the default class", accessible("s1") == ["aku"] && encrypted("s1") && describe(vault.loadValue(forKey: "s1")) == "resolve __secured_s1", "\(accessible("s1"))")
    check("17a s2 with its per-call ck class left alone", storedData("s2") == s2Before && accessible("s2") == ["ck"], "\(accessible("s2"))")
    check("17a bundle id only s3 not swept", items(account: "s3").isEmpty)
    let snapshot17 = everything()
    check("17b second sweep resolves", describe(vault.migrateLegacyValues()) == "resolve -")
    check("17b second sweep writes nothing", everything() == snapshot17)
    check("17a get copies bundle id only s3 lazily", describe(vault.loadValue(forKey: "s3")) == "resolve __secured_s3" && accessible("s3") == ["aku"] && encrypted("s3"))
}
check("17a every older copy is unchanged", legacyBefore17.count == 3 && legacySnapshot() == legacyBefore17)
cleanAll()

check("17c seed plaintext ck r1", wrapper.set("__secured_r1", forKey: "r1", withAccessibility: .afterFirstUnlock))
check("17c seed plaintext aku r2", wrapper.set("__secured_r2", forKey: "r2", withAccessibility: .whenUnlockedThisDeviceOnly))
let r3Data = vault.queue.sync { encode(vault, "__secured_r3") }
check("17c seed encrypted ck r3 written by an earlier build of this fork", r3Data.map { addRaw("r3", $0, group: sharedGroup, label: marker) } == errSecSuccess)
check("17d seed upstream-style ck item", wrapperUpstream.set("__secured_u1", forKey: "u1", withAccessibility: .afterFirstUnlock))
check("17d seed upstream standard item", wrapperUpstreamStandard.set("__secured_u2", forKey: "u2"))
let legacyBefore17c = snapshot(legacyService)
plainStrictVault.queue.sync {
    check("17c sweep without encryption resolves", describe(plainStrictVault.migrateLegacyValues()) == "resolve -")
    check("17c r1 copied as plaintext, tightened to aku", accessible("r1") == ["aku"] && storedData("r1") == [Data("__secured_r1".utf8)] && groups("r1") == [appIdGroup], "\(accessible("r1"))")
    check("17c r2 copied into the app-private group, aku and plaintext", accessible("r2") == ["aku"] && groups("r2") == [appIdGroup] && storedData("r2") == [Data("__secured_r2".utf8)], "\(groups("r2"))")
    check("17c r3 written by this fork keeps its class and bytes", accessible("r3") == ["ck"] && r3Data != nil && storedData("r3") == [r3Data!], "\(accessible("r3"))")
    check("17c a later set uses the configured class", describe(plainStrictVault.storeValue("__secured_r1b", forKey: "r1")) == "resolve true" && accessible("r1") == ["aku"] && storedData("r1") == [Data("__secured_r1b".utf8)])
}
check("17c cap_sec is unchanged", legacyBefore17c.count == 3 && snapshot(legacyService) == legacyBefore17c)
let upstreamVault = makeVault(.afterFirstUnlock, encrypts: false, currentName: upstreamCurrentService, legacyName: upstreamService, standardName: upstreamStandardService)
let upstreamBefore = snapshot(upstreamService) + snapshot(upstreamStandardService)
upstreamVault.queue.sync {
    check("17d sweep with upstream defaults resolves", describe(upstreamVault.migrateLegacyValues()) == "resolve -")
    check("17d u1 copied into the app-private group, ck and plaintext kept", accessible("u1", in: upstreamCurrentService) == ["ck"] && groups("u1", in: upstreamCurrentService) == [appIdGroup] && storedData("u1", in: upstreamCurrentService) == [Data("__secured_u1".utf8)], "\(groups("u1", in: upstreamCurrentService))")
    check("17d upstream standard item not swept", items(account: "u2", in: upstreamCurrentService).isEmpty)
    check("17d get copies the standard item as plaintext, its stricter class ak kept", describe(upstreamVault.loadValue(forKey: "u2")) == "resolve __secured_u2" && accessible("u2", in: upstreamCurrentService) == ["ak"] && storedData("u2", in: upstreamCurrentService) == [Data("__secured_u2".utf8)])
}
check("17d the upstream items are unchanged", upstreamBefore.count == 2 && snapshot(upstreamService) + snapshot(upstreamStandardService) == upstreamBefore)
cleanAll()

let sweepFlag = Flag(false)
let sweepVault = makeVault(available: { sweepFlag.read() })
check("17e seed 0.13.0 l1", wrapper.set("__secured_l1", forKey: "l1", withAccessibility: .afterFirstUnlock))
sweepVault.submitOperation(named: "sweep", key: "*", run: { sweepVault.migrateLegacyValues() })
settle(sweepVault)
check("17e sweep parked while protected data is unavailable", items(account: "l1").isEmpty)
sweepFlag.write(true)
sweepVault.drainParkedOperations()
settle(sweepVault)
check("17e sweep ran after drain", accessible("l1") == ["aku"] && encrypted("l1") && accessible("l1", in: legacyService) == ["ck"])
cleanAll()

print("--- 18 gate bypass with afterFirstUnlock default")
let bypassVault = makeVault(.afterFirstUnlock, available: { false })
log.reset()
bypassVault.submitOperation(named: "set", key: "b1", run: { bypassVault.storeValue("__secured_b1", forKey: "b1") }, completion: { log.record("set \(describe($0))") })
bypassVault.submitOperation(named: "get", key: "b1", run: { bypassVault.loadValue(forKey: "b1") }, completion: { log.record("get \(describe($0))") })
settle(bypassVault)
check("18 set and get run while protected data is unavailable", log.events == ["set resolve true", "get resolve __secured_b1"], "\(log.events)")
check("18 item stored encrypted with ck", accessible("b1") == ["ck"] && storedData("b1").first?.starts(with: magic) == true)
check("18c seed 0.13.0 item", wrapper.set("__secured_b2", forKey: "b2", withAccessibility: .afterFirstUnlock))
bypassVault.queue.sync {
    check("18c a get while protected data is unavailable reads the 0.13.0 item and writes nothing", describe(bypassVault.loadValue(forKey: "b2")) == "resolve __secured_b2" && items(account: "b2").isEmpty)
}

print("--- 19 plaintext round trip with upstream defaults")
cleanAll()
plainVault.queue.sync {
    check("19 storeValue resolves", describe(plainVault.storeValue("__secured_plain", forKey: "p1")) == "resolve true")
    check("19 stored bytes are the UTF-8 plaintext", storedData("p1") == [Data("__secured_plain".utf8)])
    check("19 class ck", accessible("p1") == ["ck"], "\(accessible("p1"))")
    check("19 loadValue resolves", describe(plainVault.loadValue(forKey: "p1")) == "resolve __secured_plain")
    check("19 SwiftKeychainWrapper reads the cap_sec_v2 item", wrapperCurrent.string(forKey: "p1") == "__secured_plain")
    check("19 overwrite", describe(plainVault.storeValue("__secured_plain2", forKey: "p1")) == "resolve true" && describe(plainVault.loadValue(forKey: "p1")) == "resolve __secured_plain2")
}
settle(plainVault)
check("19 no write-back after get", storedData("p1") == [Data("__secured_plain2".utf8)] && accessible("p1") == ["ck"])
check("19 no key created when not encrypting", allKeyCount() == 0, "\(allKeyCount())")

let emptyVault = makeVault()
emptyVault.queue.sync {
    check("19 encrypted empty value round trip", describe(emptyVault.storeValue("", forKey: "e1")) == "resolve true" && describe(emptyVault.loadValue(forKey: "e1")) == "resolve ", describe(emptyVault.loadValue(forKey: "e1")))
}
plainVault.queue.sync {
    check("19 plaintext empty value round trip", describe(plainVault.storeValue("", forKey: "e2")) == "resolve true" && describe(plainVault.loadValue(forKey: "e2")) == "resolve ", describe(plainVault.loadValue(forKey: "e2")))
}
print("--- 20 key acquisition is serialised across vault instances")
let sharedTags = tags("harness.20")
let instances = (0..<8).map { _ in makeVault(keyTag: sharedTags.name) }
let startGate = DispatchSemaphore(value: 0)
let instanceGroup = DispatchGroup()
var instanceCiphertexts: [Data?] = Array(repeating: nil, count: instances.count)
let instanceLock = NSLock()
for (index, instance) in instances.enumerated() {
    instanceGroup.enter()
    instance.queue.async {
        startGate.wait()
        let encoded = encode(instance, "__secured_shared\(index)")
        instanceLock.lock(); instanceCiphertexts[index] = encoded; instanceLock.unlock()
        instanceGroup.leave()
    }
}
for _ in instances { startGate.signal() }
instanceGroup.wait()
check("20 all instances encoded", instanceCiphertexts.allSatisfy { $0 != nil })
check("20 exactly one key created for 8 concurrent instances", keyCount(sharedTags.secureEnclave) + keyCount(sharedTags.software) == 1, "se=\(keyCount(sharedTags.secureEnclave)) sim=\(keyCount(sharedTags.software))")
let reader = makeVault(keyTag: sharedTags.name)
reader.queue.sync {
    let decoded = instanceCiphertexts.enumerated().map { index, data in data.map { describe(reader.decodeValue($0)) } == "decrypted(__secured_shared\(index))" }
    check("20 every ciphertext decrypts with the shared key", decoded.allSatisfy { $0 })
}

print("--- 21 migration never loosens the class")
cleanAll()
let relaxedEncryptingVault = makeVault(.afterFirstUnlock)
check("21 seed 0.13.0 aku item", wrapper.set("__secured_keep1", forKey: "k1", withAccessibility: .whenUnlockedThisDeviceOnly))
check("21 seed 0.13.0 akpu item", wrapper.set("__secured_keep2", forKey: "k2", withAccessibility: .whenPasscodeSetThisDeviceOnly))
check("21 seed bundle id aku item", KeychainWrapper.standard.set("__secured_keep3", forKey: "k3", withAccessibility: .whenUnlockedThisDeviceOnly))
relaxedEncryptingVault.queue.sync {
    check("21 sweep resolves", describe(relaxedEncryptingVault.migrateLegacyValues()) == "resolve -")
    check("21 sweep encrypts but keeps the stricter aku", accessible("k1") == ["aku"] && encrypted("k1"), "\(accessible("k1"))")
    check("21 sweep keeps akpu", accessible("k2") == ["akpu"] && encrypted("k2"), "\(accessible("k2"))")
    check("21 the bundle id copy keeps aku", describe(relaxedEncryptingVault.loadValue(forKey: "k3")) == "resolve __secured_keep3" && accessible("k3") == ["aku"] && encrypted("k3"), "\(accessible("k3"))")
    check("21 plain set uses the configured class", describe(relaxedEncryptingVault.storeValue("__secured_keep1b", forKey: "k1")) == "resolve true" && accessible("k1") == ["ck"])
}
check("21 the older items keep their classes", accessible("k1", in: legacyService) == ["aku"] && accessible("k2", in: legacyService) == ["akpu"] && accessible("k3", in: standardService) == ["aku"])
let lazyKeepVault = makeVault(.afterFirstUnlock)
check("21 seed 0.13.0 akpu item for get", wrapper.set("__secured_keep4", forKey: "k4", withAccessibility: .whenPasscodeSetThisDeviceOnly))
lazyKeepVault.queue.sync {
    check("21 get resolves 0.13.0 akpu", describe(lazyKeepVault.loadValue(forKey: "k4")) == "resolve __secured_keep4")
}
check("21 the copy made by get keeps akpu", accessible("k4") == ["akpu"] && encrypted("k4"), "\(accessible("k4"))")
let mixedVault = makeVault(.afterFirstUnlockThisDeviceOnly)
check("21 seed 0.13.0 ak item", wrapper.set("__secured_mix", forKey: "k5", withAccessibility: .whenUnlocked))
mixedVault.queue.sync {
    check("21 sweep combines ak and cku into aku", describe(mixedVault.migrateLegacyValues()) == "resolve -" && accessible("k5") == ["aku"], "\(accessible("k5"))")
}
let strictVault = makeVault(.whenUnlockedThisDeviceOnly)
check("21 seed 0.13.0 ck item", wrapper.set("__secured_tight", forKey: "k6", withAccessibility: .afterFirstUnlock))
strictVault.queue.sync {
    check("21 sweep tightens ck to aku", describe(strictVault.migrateLegacyValues()) == "resolve -" && accessible("k6") == ["aku"] && encrypted("k6"), "\(accessible("k6"))")
}

print("--- 22 ranking of legacy copies")
cleanAll()
let rankVault = makeVault()
let forkValues = rankVault.queue.sync { [encode(rankVault, "__secured_marked"), encode(rankVault, "__secured_marked_old"), encode(rankVault, "__secured_marked_newer")] }
check("22a seed a copy an earlier build of this fork wrote in the app-ID group", forkValues[0].map { addRaw("d5", $0, group: appIdGroup, accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, label: marker) } == errSecSuccess)
Thread.sleep(forTimeInterval: 1.1)
check("22a seed a newer unmarked 0.13.0 copy in the shared group", wrapper.set("__secured_unmarked", forKey: "d5", withAccessibility: .afterFirstUnlock) && groups("d5", in: legacyService) == [appIdGroup, sharedGroup])
rankVault.queue.sync {
    check("22a a copy this fork wrote beats a newer unmarked one", describe(rankVault.loadValue(forKey: "d5")) == "resolve __secured_marked" && currentValue(rankVault, "d5") == "decrypted(__secured_marked)")
}
check("22b seed a copy this fork wrote with a per-call ck class in the app-ID group", forkValues[1].map { addRaw("f1", $0, group: appIdGroup, accessibility: kSecAttrAccessibleAfterFirstUnlock, label: marker) } == errSecSuccess)
Thread.sleep(forTimeInterval: 1.1)
check("22b seed a newer copy it wrote with ck in the shared group during a fallback", forkValues[2].map { addRaw("f1", $0, group: sharedGroup, accessibility: kSecAttrAccessibleAfterFirstUnlock, label: marker) } == errSecSuccess)
let before22b = diagnostics(rankVault)
rankVault.queue.sync {
    check("22b the newer of two marked copies wins", describe(rankVault.loadValue(forKey: "f1")) == "resolve __secured_marked_newer" && currentValue(rankVault, "f1") == "decrypted(__secured_marked_newer)")
    check("22b the class a set of this fork chose is kept", accessible("f1") == ["ck"], "\(accessible("f1"))")
}
check("22b the older marked copy counts as conflicting", delta(before22b, diagnostics(rankVault), "conflictingDuplicates") == 1)

print("--- 24 mixed plaintext and encrypted items")
cleanAll()
let mixVault = makeVault()
check("24 seed plaintext ck in the shared group", wrapper.set("__secured_m1", forKey: "m1", withAccessibility: .afterFirstUnlock))
check("24 seed plaintext aku in the app-ID group", wrapperAppGroup.set("__secured_m2", forKey: "m2", withAccessibility: .whenUnlockedThisDeviceOnly))
var mixBefore: [String: [Data]] = [:]
mixVault.queue.sync {
    check("24 seed encrypted aku via set", describe(mixVault.storeValue("__secured_m3", forKey: "m3")) == "resolve true")
    check("24 seed encrypted per-call ck via set", describe(mixVault.storeValue("__secured_m4", forKey: "m4", accessibility: .afterFirstUnlock)) == "resolve true")
    check("24 seed an encrypted unmarked ck copy in cap_sec", encode(mixVault, "__secured_m5").map { addRaw("m5", $0, group: sharedGroup) } == errSecSuccess)
    for key in ["m3", "m4"] { mixBefore[key] = storedData(key) }
    check("24 sweep resolves", describe(mixVault.migrateLegacyValues()) == "resolve -")
}
let mixKeys = ["m1", "m2", "m3", "m4", "m5"]
check("24 every key has one cap_sec_v2 item in the app-ID group", mixKeys.allSatisfy { groups($0) == [appIdGroup] }, "\(mixKeys.map { groups($0) })")
check("24 every item encrypted", mixKeys.allSatisfy { encrypted($0) })
check("24 0.13.0 plaintext tightened to aku", accessible("m1") == ["aku"] && accessible("m2") == ["aku"])
check("24 an encrypted unmarked copy keeps its bytes and gets at least the configured class", storedData("m5") == storedData("m5", in: legacyService) && accessible("m5") == ["aku"], "\(accessible("m5"))")
check("24 items set after the upgrade keep their class and bytes", accessible("m3") == ["aku"] && accessible("m4") == ["ck"] && ["m3", "m4"].allSatisfy { storedData($0) == mixBefore[$0] })
mixVault.queue.sync {
    check("24 keys lists each key once", listed(mixVault) == mixKeys)
    check("24 every value reads back", mixKeys.allSatisfy { describe(mixVault.loadValue(forKey: $0)) == "resolve __secured_\($0)" })
}

print("--- 25 a legacy winner that cannot be decrypted")
cleanAll()
let badVault = makeVault()
let garbage25 = magic + Data(repeating: 0x5A, count: 97)
check("25 seed an older plaintext copy in the shared group", wrapper.set("__secured_older", forKey: "u1", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("25 seed a newer undecryptable copy an earlier build of this fork wrote", addRaw("u1", garbage25, group: appIdGroup, accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, label: marker) == errSecSuccess)
let legacy25 = snapshot(legacyService)
let before25 = diagnostics(badVault)
badVault.queue.sync {
    let read = badVault.loadValue(forKey: "u1")
    check("25 get reports missing with code UNREADABLE", describe(read) == "reject Item with given key does not exist" && code(read) == "UNREADABLE", "\(describe(read)) \(code(read))")
    check("25 nothing copied, the stale value is not promoted", items(account: "u1").isEmpty)
    check("25 the sweep copies nothing either", describe(badVault.migrateLegacyValues()) == "resolve -" && items(account: "u1").isEmpty)
    check("25 set writes cap_sec_v2", describe(badVault.storeValue("__secured_fresh", forKey: "u1")) == "resolve true" && describe(badVault.loadValue(forKey: "u1")) == "resolve __secured_fresh" && groups("u1") == [appIdGroup])
}
check("25 both legacy copies are unchanged, the plaintext copy is not rewritten in place", legacy25.count == 2 && snapshot(legacyService) == legacy25)
check("25 decryptFailures counted for the get and the sweep", delta(before25, diagnostics(badVault), "decryptFailures") == 2, "\(diagnostics(badVault))")
check("25b seed an older plaintext copy in the shared group", wrapper.set("__secured_older_b", forKey: "u2", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("25b seed an undecryptable copy without the label in the app-ID group", addRaw("u2", garbage25, group: appIdGroup, accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly) == errSecSuccess)
check("25b upstream 0.13.0 reads the undecryptable copy", wrapper.data(forKey: "u2") == garbage25)
badVault.queue.sync {
    check("25b get is UNREADABLE and copies nothing", code(badVault.loadValue(forKey: "u2")) == "UNREADABLE" && items(account: "u2").isEmpty)
}
check("25b the older plaintext copy stays plaintext", storedData("u2", in: legacyService).contains(Data("__secured_older_b".utf8)))
let noKeyTags = tags("harness.25.nokey")
let noKeyVault = makeVault(keyTag: noKeyTags.name)
noKeyVault.queue.sync {
    let read = noKeyVault.loadValue(forKey: "u1")
    check("25 ciphertext of a key that does not exist is UNREADABLE", describe(read) == "reject Item with given key does not exist" && code(read) == "UNREADABLE", describe(read))
    check("25 decrypting never creates a key", keyCount(noKeyTags.secureEnclave) + keyCount(noKeyTags.software) == 0)
}

print("--- 26 clear and remove only touch cap_sec_v2, cap_sec and the bundle id copies of their keys")
cleanAll()
let clearTags = tags("harness.26")
let clearVault = makeVault(keyTag: clearTags.name)
check("26 seed item under another service", addRaw("o1", Data("__secured_other".utf8), group: nil, in: otherService) == errSecSuccess)
check("26 seed item without a service (fingerprint-aio __aio_key)", SecItemAdd([kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: noServiceAccount, kSecValueData as String: Data("__secured_aio".utf8)] as CFDictionary, nil) == errSecSuccess && noServiceItemExists())
check("26 seed cap_sec item in the shared group", wrapper.set("__secured_c3", forKey: "c3", withAccessibility: .afterFirstUnlock))
clearVault.queue.sync {
    check("26 seed cap_sec_v2 items", describe(clearVault.storeValue("__secured_c1", forKey: "c1")) == "resolve true" && describe(clearVault.storeValue("__secured_c2", forKey: "c2")) == "resolve true")
    check("26 keys ignores other services", listed(clearVault) == ["c1", "c2", "c3"])
    check("26 remove of a key only another service has rejects NOT_FOUND", code(clearVault.removeValue(forKey: "o1")) == "NOT_FOUND" && items(account: "o1", in: otherService).count == 1)
    check("26 clear resolves", describe(clearVault.removeAllValues()) == "resolve true")
}
check("26 cap_sec_v2 and cap_sec empty in every group", items().isEmpty && items(in: legacyService).isEmpty)
check("26 other service item survived", storedData("o1", in: otherService) == [Data("__secured_other".utf8)])
check("26 item without a service survived", noServiceItemExists())
check("26 Secure Enclave key survived", keyCount(clearTags.secureEnclave) + keyCount(clearTags.software) == 1)
check("26 no probe items left behind", items(in: legacyService + ".probe").isEmpty)

print("--- 28 migration never loosens (all 25 pairs, encrypted lazily and plaintext via sweep)")
cleanAll()
let wrapperClasses: [(SecureStorageVault.Accessibility, KeychainItemAccessibility)] = [
    (.afterFirstUnlock, .afterFirstUnlock),
    (.afterFirstUnlockThisDeviceOnly, .afterFirstUnlockThisDeviceOnly),
    (.whenUnlocked, .whenUnlocked),
    (.whenUnlockedThisDeviceOnly, .whenUnlockedThisDeviceOnly),
    (.whenPasscodeSetThisDeviceOnly, .whenPasscodeSetThisDeviceOnly),
]
for encrypts in [true, false] {
    for (existing, wrapperClass) in wrapperClasses {
        for (configured, _) in wrapperClasses {
            let key = "n.\(encrypts).\(existing.rawValue).\(configured.rawValue)"
            let expected = existing.tightened(toAtLeast: configured).attribute as String
            let seeded = wrapper.set("__secured_n", forKey: key, withAccessibility: wrapperClass)
            let matrixVault = makeVault(configured, encrypts: encrypts)
            matrixVault.queue.sync {
                if encrypts {
                    _ = matrixVault.loadValue(forKey: key)
                } else {
                    _ = matrixVault.migrateLegacyValues()
                }
            }
            let encodingOK = encrypts ? encrypted(key) : storedData(key) == [Data("__secured_n".utf8)]
            check("28 \(encrypts ? "get" : "sweep") \(existing.rawValue) + \(configured.rawValue) -> \(expected)", seeded && accessible(key) == [expected] && groups(key) == [appIdGroup] && encodingOK && accessible(key, in: legacyService) == [existing.attribute as String], "\(accessible(key)) \(groups(key))")
        }
    }
}
let keepVault = makeVault(.whenPasscodeSetThisDeviceOnly)
for (perCall, _) in wrapperClasses {
    let key = "keep.\(perCall.rawValue)"
    keepVault.queue.sync {
        _ = keepVault.storeValue("__secured_keep", forKey: key, accessibility: perCall)
        _ = keepVault.migrateLegacyValues()
    }
    check("28 a per-call \(perCall.rawValue) survives the sweep under a stricter default", accessible(key) == [perCall.attribute as String], "\(accessible(key))")
}

print("--- 29 Secure Enclave key class follows the configured class")
cleanAll()
for (configured, expected) in [(SecureStorageVault.Accessibility.whenUnlockedThisDeviceOnly, "aku"), (.whenUnlocked, "aku"), (.whenPasscodeSetThisDeviceOnly, "aku"), (.afterFirstUnlock, "cku"), (.afterFirstUnlockThisDeviceOnly, "cku")] {
    let classTags = tags("harness.29.\(configured.rawValue)")
    let classVault = makeVault(configured, keyTag: classTags.name)
    classVault.queue.sync {
        let roundTrip = encode(classVault, "__secured_kc").map { describe(classVault.decodeValue($0)) } ?? "encode failed"
        let acl = classVault.keyAccessControlDescription() ?? "nil"
        check("29 \(configured.rawValue) -> key \(expected), privateKeyUsage only, app-ID group", roundTrip == "decrypted(__secured_kc)" && acl.hasPrefix("<SecAccessControlRef: \(expected);") && !acl.contains("bio") && !acl.contains("cpo") && keyAttributes(classTags.secureEnclave).first?[kSecAttrAccessGroup as String] as? String == appIdGroup, acl)
    }
}

print("--- 30 plaintext fallback when encryption fails")
cleanAll()
let plainFallbackVault = makeVault(.afterFirstUnlock)
plainFallbackVault.queue.sync {
    plainFallbackVault.simulatesEncryptionFailure = true
    check("30 set resolves instead of rejecting", describe(plainFallbackVault.storeValue("__secured_pf", forKey: "pf1")) == "resolve true")
    check("30 stored as plaintext with at least aku", storedData("pf1") == [Data("__secured_pf".utf8)] && accessible("pf1") == ["aku"] && groups("pf1") == [appIdGroup], "\(accessible("pf1"))")
    check("30 get returns it", describe(plainFallbackVault.loadValue(forKey: "pf1")) == "resolve __secured_pf")
    check("30 a stricter per-call class stays", describe(plainFallbackVault.storeValue("__secured_pf2", forKey: "pf2", accessibility: .whenPasscodeSetThisDeviceOnly)) == "resolve true" && accessible("pf2") == ["akpu"])
    check("30 seed 0.13.0 ck", wrapper.set("__secured_pf3", forKey: "pf3", withAccessibility: .afterFirstUnlock))
    check("30 migration falls back too: plaintext, aku, app-ID group", describe(plainFallbackVault.loadValue(forKey: "pf3")) == "resolve __secured_pf3" && storedData("pf3") == [Data("__secured_pf3".utf8)] && accessible("pf3") == ["aku"] && groups("pf3") == [appIdGroup], "\(accessible("pf3")) \(groups("pf3"))")
    plainFallbackVault.simulatesEncryptionFailure = false
    let snapshot30 = snapshot(currentService)
    check("30 the sweep leaves plaintext cap_sec_v2 items alone", describe(plainFallbackVault.migrateLegacyValues()) == "resolve -" && snapshot(currentService) == snapshot30)
    let values30 = ["pf1": "__secured_pf", "pf2": "__secured_pf2", "pf3": "__secured_pf3"]
    check("30 get encrypts them in place once encryption works, classes kept", values30.allSatisfy { describe(plainFallbackVault.loadValue(forKey: $0.key)) == "resolve \($0.value)" } && ["pf1", "pf2", "pf3"].allSatisfy { encrypted($0) } && accessible("pf1") == ["aku"] && accessible("pf2") == ["akpu"] && accessible("pf3") == ["aku"], "\(accessible("pf1")) \(accessible("pf2")) \(accessible("pf3"))")
    check("30 values still read back", values30.allSatisfy { describe(plainFallbackVault.loadValue(forKey: $0.key)) == "resolve \($0.value)" })
}
check("30 diagnostics count three plaintext fallbacks", counter(diagnostics(plainFallbackVault), "plaintextFallbacks") == 3, "\(diagnostics(plainFallbackVault))")
check("30 the 0.13.0 item stays plaintext ck", storedData("pf3", in: legacyService) == [Data("__secured_pf3".utf8)] && accessible("pf3", in: legacyService) == ["ck"])

print("--- 31 lost items with the real keychain and unlock probe, phase 2")
cleanAll()
let lostTicker = HarnessTicker()
let lostVault = SecureStorageVault(configuration: phaseTwo, bundleIdentifier: harnessBundle, isProtectedDataAvailable: { true }, ticker: lostTicker)
let lostLog = EventLog()
check("31 seed two 0.13.0 copies of z1", wrapperAppGroup.set("__secured_z_old", forKey: "z1", withAccessibility: .afterFirstUnlock) && wrapper.set("__secured_z_new", forKey: "z1", withAccessibility: .afterFirstUnlock))
check("31 seed z2 and z3", wrapper.set("__secured_z2", forKey: "z2", withAccessibility: .afterFirstUnlock) && wrapper.set("__secured_z3", forKey: "z3", withAccessibility: .afterFirstUnlock))
lostVault.submitOperation(named: "set", key: "z1", run: { .locked }, lost: { lostVault.replaceLostValue("__secured_replaced", forKey: "z1") }, completion: { lostLog.record("set \(describe($0))") })
lostVault.queue.sync {}
lostTicker.fire(times: 2)
check("31 a stuck set waits through two retries", lostLog.events.isEmpty)
lostTicker.fire()
check("31 then the lost set writes a fresh cap_sec_v2 item and phase 2 deletes the legacy copies", lostLog.events == ["set resolve true"] && groups("z1") == [appIdGroup] && items(account: "z1", in: legacyService).isEmpty && lostVault.queue.sync { describe(lostVault.loadValue(forKey: "z1")) } == "resolve __secured_replaced", "\(lostLog.events) \(groups("z1"))")
lostVault.submitOperation(named: "get", key: "z2", run: { .locked }, lost: { lostVault.lostValue(forKey: "z2") }, completion: { lostLog.record("get \(describe($0)) \(code($0))") })
lostVault.submitOperation(named: "remove", key: "z2", run: { .locked }, lost: { lostVault.removeLostValue(forKey: "z2") }, completion: { lostLog.record("remove \(describe($0))") })
lostVault.queue.sync {}
lostTicker.fire(times: 3)
check("31 a lost get rejects as missing UNREADABLE", lostLog.events.contains("get reject Item with given key does not exist UNREADABLE"), "\(lostLog.events)")
lostTicker.fire(times: 3)
check("31 a lost remove deletes every copy and resolves", lostLog.events.last == "remove resolve true" && items(account: "z2").isEmpty && items(account: "z2", in: legacyService).isEmpty, "\(lostLog.events)")
lostVault.submitOperation(named: "clear", key: "*", run: { .locked }, lost: { lostVault.removeAllLostValues() }, completion: { lostLog.record("clear \(describe($0))") })
lostVault.queue.sync {}
lostTicker.fire(times: 3)
check("31 a lost clear deletes cap_sec_v2 and cap_sec and resolves", lostLog.events.last == "clear resolve true" && items().isEmpty && items(in: legacyService).isEmpty)
check("31 lostItems counted", counter(diagnostics(lostVault), "lostItems") == 4 && counter(diagnostics(lostVault), "parked") == 4, "\(diagnostics(lostVault))")
check("31 the unlock probe leaves no items behind", items(in: legacyService + ".probe").isEmpty)

print("--- 32 a parked get waits for the gate, then copies the value")
cleanAll()
let gateFlag = Flag(false)
let gateTicker = HarnessTicker()
let gateVault = SecureStorageVault(bundleIdentifier: harnessBundle, isProtectedDataAvailable: { gateFlag.read() }, ticker: gateTicker)
let gateLog = EventLog()
check("32 seed 0.13.0 pin in the shared group", wrapper.set("__secured_1234", forKey: "pin", withAccessibility: .afterFirstUnlock))
let pin32 = snapshot(legacyService)
gateVault.submitOperation(named: "get", key: "pin", run: { gateVault.loadValue(forKey: "pin") }, lost: { gateVault.lostValue(forKey: "pin") }, completion: { gateLog.record("get \(describe($0))") })
gateVault.queue.sync {}
gateTicker.fire(times: 10)
check("32 parked while locked, nothing copied", gateLog.events.isEmpty && items(account: "pin").isEmpty)
gateFlag.write(true)
gateTicker.fire()
check("32 resolves with the value after unlock, copied into cap_sec_v2", gateLog.events == ["get resolve __secured_1234"] && groups("pin") == [appIdGroup] && encrypted("pin") && accessible("pin") == ["aku"], "\(gateLog.events)")
check("32 the 0.13.0 item is unchanged", snapshot(legacyService) == pin32)

print("--- 33 decryption failures on an unlocked device")
cleanAll()
// cleanAll deletes the keys but not the process-wide key reference cache, so a section that retries a lookup needs its own tag.
let retryTags = tags("harness.33")
let retryVault = makeVault(keyTag: retryTags.name)
retryVault.queue.sync {
    check("33 seed encrypted value", describe(retryVault.storeValue("__secured_retry", forKey: "r1")) == "resolve true")
    var calls = 0
    retryVault.decryptCiphertext = { key, algorithm, ciphertext, error in
        calls += 1
        guard calls > 1 else {
            error?.pointee = osStatusError(errSecInternalError)
            return nil
        }
        return SecKeyCreateDecryptedData(key, algorithm, ciphertext, error)
    }
    let retriesBefore = retryVault.counters.decryptRetries
    check("33 a transient failure is retried with a fresh key lookup and get resolves", describe(retryVault.loadValue(forKey: "r1")) == "resolve __secured_retry" && calls == 2 && retryVault.counters.decryptRetries - retriesBefore == 1, "\(calls)")
    retryVault.decryptCiphertext = { _, _, _, error in
        error?.pointee = osStatusError(errSecInternalError)
        return nil
    }
    check("33 a failure that is not known to be permanent parks instead of UNREADABLE", describe(retryVault.loadValue(forKey: "r1")) == "locked")
    retryVault.decryptCiphertext = { _, _, _, error in
        error?.pointee = osStatusError(errSecDecode)
        return nil
    }
    let decodeRead = retryVault.loadValue(forKey: "r1")
    check("33 errSecDecode after the retries is UNREADABLE", code(decodeRead) == "UNREADABLE", describe(decodeRead))
    retryVault.decryptCiphertext = SecKeyCreateDecryptedData
    check("33 nothing was deleted, the value still reads back", describe(retryVault.loadValue(forKey: "r1")) == "resolve __secured_retry" && items(account: "r1").count == 1)
}
let parkTicker = HarnessTicker()
let parkVault = SecureStorageVault(keyTag: retryTags.name, bundleIdentifier: harnessBundle, isProtectedDataAvailable: { true }, ticker: parkTicker)
let parkLog = EventLog()
parkVault.queue.sync {
    parkVault.decryptRetryDelays = [0, 0]
    parkVault.decryptCiphertext = { _, _, _, error in
        error?.pointee = osStatusError(errSecInternalError)
        return nil
    }
}
parkVault.submitOperation(named: "get", key: "r1", run: { parkVault.loadValue(forKey: "r1") }, lost: { parkVault.lostValue(forKey: "r1") }, completion: { parkLog.record("get \(describe($0)) \(code($0))") })
parkVault.queue.sync {}
parkTicker.fire(times: 2)
check("33 a get that keeps failing waits through the tick retries", parkLog.events.isEmpty, "\(parkLog.events)")
parkTicker.fire()
check("33 then rejects as missing UNREADABLE, the key failing everywhere is unusable for the process", parkLog.events == ["get reject Item with given key does not exist UNREADABLE"] && counter(diagnostics(parkVault), "lostItems") == 0 && diagnostics(parkVault)["keyBackend"] as? String == "unusable", "\(parkLog.events) \(diagnostics(parkVault))")
check("33 the item is untouched", items(account: "r1").count == 1 && encrypted("r1"))
parkVault.submitOperation(named: "get", key: "r1", run: { parkVault.loadValue(forKey: "r1") }, lost: { parkVault.lostValue(forKey: "r1") }, completion: { parkLog.record("get \(describe($0)) \(code($0))") })
parkVault.queue.sync {}
check("33 the next get rejects at once", parkLog.events.count == 2 && parkLog.events.last == "get reject Item with given key does not exist UNREADABLE", "\(parkLog.events)")
parkVault.queue.sync {
    check("33 a set stores plaintext with the strict class", describe(parkVault.storeValue("__secured_r2", forKey: "r2")) == "resolve true" && storedData("r2") == [Data("__secured_r2".utf8)] && accessible("r2") == ["aku"], "\(accessible("r2"))")
}
check("33 the key is kept", keyCount(retryTags.secureEnclave) + keyCount(retryTags.software) == 1)
// A failure that only this ciphertext shows: the key still opens fresh ciphertext, so only this call ends, as lost.
let brokenCiphertext = storedData("r1").first.map { Data($0.dropFirst(magic.count)) }
let itemTicker = HarnessTicker()
let itemVault = SecureStorageVault(keyTag: retryTags.name, bundleIdentifier: harnessBundle, isProtectedDataAvailable: { true }, ticker: itemTicker)
let itemLog = EventLog()
itemVault.queue.sync {
    itemVault.decryptRetryDelays = [0, 0]
    itemVault.decryptCiphertext = { key, algorithm, ciphertext, error in
        guard (ciphertext as Data) != brokenCiphertext else {
            error?.pointee = osStatusError(errSecInternalError)
            return nil
        }
        return SecKeyCreateDecryptedData(key, algorithm, ciphertext, error)
    }
    check("33 seed a second encrypted value", describe(itemVault.storeValue("__secured_r3", forKey: "r3")) == "resolve true" && encrypted("r3"))
}
itemVault.submitOperation(named: "get", key: "r1", run: { itemVault.loadValue(forKey: "r1") }, lost: { itemVault.lostValue(forKey: "r1") }, completion: { itemLog.record("get \(describe($0)) \(code($0))") })
itemVault.queue.sync {}
itemTicker.fire(times: 3)
check("33 a failure of one ciphertext rejects that get through the lost escape", itemLog.events == ["get reject Item with given key does not exist UNREADABLE"] && counter(diagnostics(itemVault), "lostItems") == 1, "\(itemLog.events) \(diagnostics(itemVault))")
check("33 and keeps the key usable for the other items", diagnostics(itemVault)["keyBackend"] as? String != "unusable" && itemVault.queue.sync { describe(itemVault.loadValue(forKey: "r3")) } == "resolve __secured_r3", "\(diagnostics(itemVault))")

print("--- 34 a key that keeps refusing with -25308 while unlocked (Quick Start zombie)")
cleanAll()
let zombieTags = tags("harness.34")
let zombieTicker = HarnessTicker()
let zombieVault = SecureStorageVault(keyTag: zombieTags.name, bundleIdentifier: harnessBundle, isProtectedDataAvailable: { true }, ticker: zombieTicker)
let zombieLog = EventLog()
zombieVault.queue.sync {
    check("34 seed an encrypted value while the key works", describe(zombieVault.storeValue("__secured_z1", forKey: "zk1")) == "resolve true" && encrypted("zk1"))
    zombieVault.forgetCachedKey()
    zombieVault.copyMatchingKey = { _, _ in errSecInteractionNotAllowed }
}
zombieVault.submitOperation(named: "set", key: "zk2", run: { zombieVault.storeValue("__secured_z2", forKey: "zk2") }, lost: { zombieVault.replaceLostValue("__secured_z2", forKey: "zk2") }, completion: { zombieLog.record("set \(describe($0))") })
zombieVault.queue.sync {}
zombieTicker.fire(times: 2)
check("34 set waits while the refusals are counted", zombieLog.events.isEmpty, "\(zombieLog.events)")
zombieTicker.fire()
check("34 then stores plaintext with the strict class instead of parking for ever", zombieLog.events == ["set resolve true"] && storedData("zk2") == [Data("__secured_z2".utf8)] && accessible("zk2") == ["aku"] && groups("zk2") == [appIdGroup], "\(zombieLog.events) \(accessible("zk2"))")
let zombieDiagnostics = diagnostics(zombieVault)
check("34 diagnostics: keyBackend unusable, one plaintext fallback, no lost item", zombieDiagnostics["keyBackend"] as? String == "unusable" && counter(zombieDiagnostics, "plaintextFallbacks") == 1 && counter(zombieDiagnostics, "lostItems") == 0, "\(zombieDiagnostics)")
zombieVault.queue.sync {
    let read = zombieVault.loadValue(forKey: "zk1")
    check("34 ciphertext of the refused key reads as missing UNREADABLE right away", code(read) == "UNREADABLE", describe(read))
    check("34 the plaintext fallback reads back and stays plaintext", describe(zombieVault.loadValue(forKey: "zk2")) == "resolve __secured_z2" && storedData("zk2") == [Data("__secured_z2".utf8)])
}
check("34 the ciphertext item and the key are kept", encrypted("zk1") && items(account: "zk1").count == 1 && keyCount(zombieTags.secureEnclave) + keyCount(zombieTags.software) == 1)
let zombieReader = makeVault(keyTag: zombieTags.name)
zombieReader.queue.sync {
    check("34 a process whose key works again still decrypts the kept ciphertext", describe(zombieReader.loadValue(forKey: "zk1")) == "resolve __secured_z1")
}

print("--- 35 ciphertext is checked before it is written")
cleanAll()
/// The real decryption for the first `successes` calls, `errSecParam` afterwards.
func decryptionFailing(after successes: Int) -> (SecKey, SecKeyAlgorithm, CFData, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? {
    var calls = 0
    return { key, algorithm, ciphertext, error in
        calls += 1
        guard calls > successes else { return SecKeyCreateDecryptedData(key, algorithm, ciphertext, error) }
        error?.pointee = osStatusError(errSecParam)
        return nil
    }
}
let checkTags = tags("harness.35")
let checkVault = makeVault(keyTag: checkTags.name)
checkVault.queue.sync {
    checkVault.decryptRetryDelays = [0, 0]
    checkVault.decryptCiphertext = decryptionFailing(after: 0)
    let fallbacksBefore = checkVault.counters.plaintextFallbacks
    check("35 a set whose ciphertext does not decrypt stores plaintext with the strict class", describe(checkVault.storeValue("__secured_c0", forKey: "c0")) == "resolve true" && storedData("c0") == [Data("__secured_c0".utf8)] && accessible("c0") == ["aku"] && checkVault.counters.plaintextFallbacks - fallbacksBefore == 1, "\(accessible("c0"))")
    check("35 seed 0.13.0 plaintext in the shared group", wrapper.set("__secured_c1", forKey: "c1", withAccessibility: .afterFirstUnlock))
    check("35 get of a 0.13.0 value whose new ciphertext does not decrypt returns the value", describe(checkVault.loadValue(forKey: "c1")) == "resolve __secured_c1")
    check("35 that copy fell back to plaintext with the strict class and the value still reads back", storedData("c1") == [Data("__secured_c1".utf8)] && accessible("c1") == ["aku"] && groups("c1") == [appIdGroup] && describe(checkVault.loadValue(forKey: "c1")) == "resolve __secured_c1", "\(accessible("c1")) \(groups("c1"))")

    // The check in memory passes, the read-back after the write does not.
    check("35 seed 0.13.0 plaintext in the app-ID group", wrapperAppGroup.set("__secured_c2", forKey: "c2", withAccessibility: .afterFirstUnlock))
    checkVault.decryptCiphertext = decryptionFailing(after: 1)
    check("35 get returns the 0.13.0 value although the new item does not verify", describe(checkVault.loadValue(forKey: "c2")) == "resolve __secured_c2")
    check("35 the unverified cap_sec_v2 item is deleted again", items(account: "c2").isEmpty)
    checkVault.decryptCiphertext = decryptionFailing(after: 1)
    check("35 get of a plaintext cap_sec_v2 item whose encryption does not verify returns the value", describe(checkVault.loadValue(forKey: "c1")) == "resolve __secured_c1")
    check("35 and puts the plaintext back with its class", storedData("c1") == [Data("__secured_c1".utf8)] && accessible("c1") == ["aku"])
    checkVault.decryptCiphertext = SecKeyCreateDecryptedData
    check("35 once decryption works the sweep copies c2", describe(checkVault.migrateLegacyValues()) == "resolve -" && encrypted("c2") && groups("c2") == [appIdGroup] && accessible("c2") == ["aku"])
    check("35 and get encrypts c1 in place", describe(checkVault.loadValue(forKey: "c1")) == "resolve __secured_c1" && encrypted("c1") && accessible("c1") == ["aku"])
    check("35 the values read back", describe(checkVault.loadValue(forKey: "c2")) == "resolve __secured_c2" && describe(checkVault.loadValue(forKey: "c1")) == "resolve __secured_c1")
}
check("35 the 0.13.0 items are unchanged", storedData("c1", in: legacyService) == [Data("__secured_c1".utf8)] && storedData("c2", in: legacyService) == [Data("__secured_c2".utf8)] && accessible("c1", in: legacyService) == ["ck"] && accessible("c2", in: legacyService) == ["ck"])

print("--- A upgrade from 0.13.0 with copies in the app-ID group and the shared group")
cleanAll()
let upgrade = makeVault()
check("A seed pin in the app-ID group", wrapperAppGroup.set("__secured_pin_app", forKey: "pin", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 1.1)
check("A seed pin in the shared group", wrapper.set("__secured_pin_shared", forKey: "pin", withAccessibility: .whenUnlocked))
Thread.sleep(forTimeInterval: 1.1)
check("A seed token in the shared group", wrapper.set("__secured_token_shared", forKey: "token", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 1.1)
check("A seed token in the app-ID group", wrapperAppGroup.set("__secured_token_app", forKey: "token", withAccessibility: .afterFirstUnlockThisDeviceOnly))
let seededA = snapshot(legacyService)
let datesA = Set(items(in: legacyService).compactMap { $0[kSecAttrModificationDate as String] as? Date })
check("A four 0.13.0 items with four values and four dates", seededA.count == 4 && datesA.count == 4 && Set(storedData("pin", in: legacyService) + storedData("token", in: legacyService)).count == 4 && groups("pin", in: legacyService) == [appIdGroup, sharedGroup] && groups("token", in: legacyService) == [appIdGroup, sharedGroup])
let upstreamPin = wrapper.string(forKey: "pin") ?? "nil"
let upstreamToken = wrapper.string(forKey: "token") ?? "nil"
check("A the upstream read differs from the newest copy at least once, so the rule is exercised", upstreamPin == "__secured_pin_app" || upstreamToken == "__secured_token_shared", "\(upstreamPin) \(upstreamToken)")
let beforeA = diagnostics(upgrade)
upgrade.queue.sync {
    check("A get returns the value the 0.13.0 query returns", describe(upgrade.loadValue(forKey: "pin")) == "resolve \(upstreamPin)", upstreamPin)
    check("A after get: one cap_sec_v2 pin in the app-ID group, encrypted, aku, holding that value", groups("pin") == [appIdGroup] && encrypted("pin") && accessible("pin") == ["aku"] && currentValue(upgrade, "pin") == "decrypted(\(upstreamPin))", "\(groups("pin"))")
    check("A after get: token is not copied yet", items(account: "token").isEmpty)
}
check("A after get: the four 0.13.0 items are byte-identical (data, class, group, label, date)", snapshot(legacyService) == seededA)
upgrade.queue.sync {
    check("A sweep resolves", describe(upgrade.migrateLegacyValues()) == "resolve -")
    check("A after the sweep: one cap_sec_v2 token in the app-ID group, encrypted, aku, holding the value the 0.13.0 query returns", groups("token") == [appIdGroup] && encrypted("token") && accessible("token") == ["aku"] && currentValue(upgrade, "token") == "decrypted(\(upstreamToken))", "\(groups("token"))")
    check("A after the sweep: one cap_sec_v2 item per key", items().count == 2 && groups("pin") == [appIdGroup])
}
check("A after the sweep: the four 0.13.0 items are byte-identical", snapshot(legacyService) == seededA)
let afterA = diagnostics(upgrade)
check("A diagnostics: two keys migrated, the other copy of each held another value, nothing deleted, two keys with older copies kept", delta(beforeA, afterA, "migrated") == 2 && delta(beforeA, afterA, "conflictingDuplicates") == 2 && delta(beforeA, afterA, "duplicatesResolved") == 0 && delta(beforeA, afterA, "legacyCopiesKept") == 2, "\(afterA)")
let currentA = snapshot(currentService)
upgrade.queue.sync {
    check("A the next gets return the same values and write nothing", describe(upgrade.loadValue(forKey: "pin")) == "resolve \(upstreamPin)" && describe(upgrade.loadValue(forKey: "token")) == "resolve \(upstreamToken)" && snapshot(currentService) == currentA)
}

print("--- B the sweep of the next launch")
Thread.sleep(forTimeInterval: 1.1)
let nextLaunch = makeVault()
let decryptionsB = Tally()
let everythingB = everything()
nextLaunch.queue.sync {
    nextLaunch.decryptCiphertext = { key, algorithm, ciphertext, error in
        decryptionsB.add()
        return SecKeyCreateDecryptedData(key, algorithm, ciphertext, error)
    }
    check("B the sweep resolves", describe(nextLaunch.migrateLegacyValues()) == "resolve -")
}
check("B it writes nothing: every item of cap_sec_v2, cap_sec and the bundle id service is byte-identical with the same date", everythingB.count == 6 && everything() == everythingB)
check("B it decrypts nothing", decryptionsB.read() == 0, "\(decryptionsB.read())")
let diagnosticsB = diagnostics(nextLaunch)
check("B diagnostics: nothing migrated or deleted, two keys with older copies kept", counter(diagnosticsB, "migrated") == 0 && counter(diagnosticsB, "duplicatesResolved") == 0 && counter(diagnosticsB, "conflictingDuplicates") == 0 && counter(diagnosticsB, "legacyCopiesKept") == 2, "\(diagnosticsB)")
nextLaunch.queue.sync { nextLaunch.decryptCiphertext = SecKeyCreateDecryptedData }

print("--- C set after the upgrade, and a downgrade to 0.13.0")
upgrade.queue.sync {
    check("C set resolves", describe(upgrade.storeValue("__secured_pin_new", forKey: "pin")) == "resolve true")
    check("C get returns the new value", describe(upgrade.loadValue(forKey: "pin")) == "resolve __secured_pin_new")
    check("C set changed the cap_sec_v2 item only", currentValue(upgrade, "pin") == "decrypted(__secured_pin_new)" && groups("pin") == [appIdGroup])
}
check("C every 0.13.0 item is still byte-identical", snapshot(legacyService) == seededA)
check("C the 0.13.0 query still returns the pre-upgrade values", wrapper.string(forKey: "pin") == upstreamPin && wrapper.string(forKey: "token") == upstreamToken)
Thread.sleep(forTimeInterval: 1.1)
check("C a 0.13.0 build writes the shared copy again", touch("pin", in: sharedGroup, "__secured_pin_downgrade") == errSecSuccess)
check("C that copy is now newer by date than the cap_sec_v2 item", (modified("pin", in: sharedGroup, service: legacyService) ?? .distantPast) > (modified("pin", in: appIdGroup) ?? .distantFuture))
let currentC = snapshot(currentService)
upgrade.queue.sync {
    check("C get still returns the cap_sec_v2 value", describe(upgrade.loadValue(forKey: "pin")) == "resolve __secured_pin_new")
    check("C the sweep leaves the key alone", describe(upgrade.migrateLegacyValues()) == "resolve -" && snapshot(currentService) == currentC)
}

print("--- D remove, clear and keys")
cleanAll()
let wipe = makeVault()
check("D seed k1 in two groups", wrapperAppGroup.set("__secured_k1_app", forKey: "k1", withAccessibility: .afterFirstUnlock) && wrapper.set("__secured_k1_shared", forKey: "k1", withAccessibility: .afterFirstUnlock))
check("D seed k2 in the shared group and the bundle id service", wrapper.set("__secured_k2", forKey: "k2", withAccessibility: .afterFirstUnlock) && KeychainWrapper.standard.set("__secured_k2_std", forKey: "k2"))
check("D seed bundle id only k3 and an item of another key", KeychainWrapper.standard.set("__secured_k3", forKey: "k3") && KeychainWrapper.standard.set("__secured_foreign", forKey: "foreign"))
wipe.queue.sync {
    check("D seed k4 with set", describe(wipe.storeValue("__secured_k4", forKey: "k4")) == "resolve true")
    check("D keys before the migration: cap_sec_v2 and cap_sec, each key once, bundle id items not listed", listed(wipe) == ["k1", "k2", "k4"], "\(listed(wipe) ?? [])")
    check("D get of k1 and k3 and the sweep copy k1, k2 and k3", describe(wipe.loadValue(forKey: "k1")).hasPrefix("resolve __secured_k1_") && describe(wipe.loadValue(forKey: "k3")) == "resolve __secured_k3" && describe(wipe.migrateLegacyValues()) == "resolve -" && ["k1", "k2", "k3", "k4"].allSatisfy { items(account: $0).count == 1 })
    check("D keys after the migration: the union, each key once", listed(wipe) == ["k1", "k2", "k3", "k4"], "\(listed(wipe) ?? [])")
    check("D remove deletes the cap_sec_v2 item and both cap_sec copies", describe(wipe.removeValue(forKey: "k1")) == "resolve true" && items(account: "k1").isEmpty && items(account: "k1", in: legacyService).isEmpty)
    check("D a removed key stays missing, no older copy comes back", code(wipe.loadValue(forKey: "k1")) == "NOT_FOUND")
    check("D remove deletes the cap_sec_v2 item and the bundle id copy", describe(wipe.removeValue(forKey: "k3")) == "resolve true" && items(account: "k3").isEmpty && !KeychainWrapper.standard.hasValue(forKey: "k3"))
    check("D seed k5 in cap_sec only", wrapper.set("__secured_k5", forKey: "k5", withAccessibility: .afterFirstUnlock))
    check("D remove deletes a key that only has a cap_sec copy", describe(wipe.removeValue(forKey: "k5")) == "resolve true" && items(account: "k5", in: legacyService).isEmpty && items(account: "k5").isEmpty)
    check("D remove of a missing key rejects NOT_FOUND", code(wipe.removeValue(forKey: "k1")) == "NOT_FOUND")
    check("D seed k6 in cap_sec only", wrapper.set("__secured_k6", forKey: "k6", withAccessibility: .afterFirstUnlock))
    check("D keys lists k6 before clear", listed(wipe) == ["k2", "k4", "k6"], "\(listed(wipe) ?? [])")
    check("D clear resolves", describe(wipe.removeAllValues()) == "resolve true")
    check("D clear wiped cap_sec_v2 and cap_sec in every group", items().isEmpty && items(in: legacyService).isEmpty)
    check("D clear deleted the bundle id copy of a listed key and kept the bundle id item of another key", !KeychainWrapper.standard.hasValue(forKey: "k2") && KeychainWrapper.standard.string(forKey: "foreign") == "__secured_foreign")
    check("D keys after clear is empty", listed(wipe) == [])
}
_ = KeychainWrapper.standard.removeObject(forKey: "foreign")

print("--- E a bundle id service item (upstream up to 0.4.0)")
cleanAll()
let bundleVault = makeVault()
check("E seed bundle id item", KeychainWrapper.standard.set("__secured_tok", forKey: "token"))
let tokenStandard = snapshot(standardService)
bundleVault.queue.sync {
    check("E keys does not list it and the sweep does not copy it", listed(bundleVault) == [] && describe(bundleVault.migrateLegacyValues()) == "resolve -" && items(account: "token").isEmpty)
    check("E get copies it into cap_sec_v2", describe(bundleVault.loadValue(forKey: "token")) == "resolve __secured_tok")
    check("E cap_sec_v2 has one encrypted aku item in the app-ID group, nothing went into cap_sec", groups("token") == [appIdGroup] && accessible("token") == ["aku"] && encrypted("token") && items(in: legacyService).isEmpty, "\(groups("token"))")
    check("E keys lists it now", listed(bundleVault) == ["token"])
    check("E the second get reads cap_sec_v2", describe(bundleVault.loadValue(forKey: "token")) == "resolve __secured_tok")
    check("E get of a key missing everywhere rejects NOT_FOUND", code(bundleVault.loadValue(forKey: "nothing")) == "NOT_FOUND")
    check("E the sweep keeps the bundle id item", describe(bundleVault.migrateLegacyValues()) == "resolve -")
}
check("E the bundle id item stays as it was", tokenStandard.count == 1 && snapshot(standardService) == tokenStandard && KeychainWrapper.standard.string(forKey: "token") == "__secured_tok")
check("E diagnostics: one key migrated, one key with an older copy kept", counter(diagnostics(bundleVault), "migrated") == 1 && counter(diagnostics(bundleVault), "legacyCopiesKept") == 1, "\(diagnostics(bundleVault))")
check("E seed bundle id item for the plaintext vault", KeychainWrapper.standard.set("__secured_ptok", forKey: "plainToken"))
plainVault.queue.sync {
    check("E get copies it without encryption", describe(plainVault.loadValue(forKey: "plainToken")) == "resolve __secured_ptok")
    check("E cap_sec_v2 has plaintext, the stricter bundle id class ak kept", accessible("plainToken") == ["ak"] && storedData("plainToken") == [Data("__secured_ptok".utf8)], "\(accessible("plainToken"))")
}
check("E that bundle id item stays too", KeychainWrapper.standard.string(forKey: "plainToken") == "__secured_ptok")
check("E seed a cap_sec copy", wrapper.set("__secured_cap", forKey: "std2", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 1.1)
check("E seed a newer bundle id copy", KeychainWrapper.standard.set("__secured_newer_std", forKey: "std2"))
bundleVault.queue.sync {
    check("E the cap_sec copy wins over a newer bundle id copy", describe(bundleVault.loadValue(forKey: "std2")) == "resolve __secured_cap" && currentValue(bundleVault, "std2") == "decrypted(__secured_cap)")
}
check("E both older copies stay", wrapper.string(forKey: "std2") == "__secured_cap" && KeychainWrapper.standard.string(forKey: "std2") == "__secured_newer_std")

print("--- F phase 2 deletes the legacy copies")
cleanAll()
let earlier = makeVault()
check("F seed n1 in two groups and the bundle id service", wrapper.set("__secured_n1_shared", forKey: "n1", withAccessibility: .afterFirstUnlock) && wrapperOlderGroup.set("__secured_n1_older", forKey: "n1", withAccessibility: .afterFirstUnlock) && KeychainWrapper.standard.set("__secured_n1_std", forKey: "n1"))
check("F seed bundle id only n6", KeychainWrapper.standard.set("__secured_n6", forKey: "n6"))
let upstreamN1 = wrapper.string(forKey: "n1") ?? "nil"
earlier.queue.sync {
    check("F phase 1 copies n1 and n6 and keeps their older copies", describe(earlier.loadValue(forKey: "n1")) == "resolve \(upstreamN1)" && describe(earlier.loadValue(forKey: "n6")) == "resolve __secured_n6" && items(account: "n1", in: legacyService).count == 2 && KeychainWrapper.standard.hasValue(forKey: "n1") && KeychainWrapper.standard.hasValue(forKey: "n6"))
}
let n1Current = snapshot(currentService, account: "n1")
let n6Current = snapshot(currentService, account: "n6")
check("F seed n2 in two groups with two values", wrapperAppGroup.set("__secured_n2_app", forKey: "n2", withAccessibility: .afterFirstUnlock) && wrapper.set("__secured_n2_shared", forKey: "n2", withAccessibility: .afterFirstUnlock))
check("F seed bundle id only n3", KeychainWrapper.standard.set("__secured_n3", forKey: "n3"))
check("F seed n4 in two groups with two values", wrapperAppGroup.set("__secured_n4_app", forKey: "n4", withAccessibility: .afterFirstUnlock) && wrapper.set("__secured_n4_shared", forKey: "n4", withAccessibility: .afterFirstUnlock))
check("F seed n5 in cap_sec and the bundle id service", wrapper.set("__secured_n5_old", forKey: "n5", withAccessibility: .afterFirstUnlock) && KeychainWrapper.standard.set("__secured_n5_std", forKey: "n5"))
check("F seed a bundle id item of another key", KeychainWrapper.standard.set("__secured_foreign", forKey: "foreign"))
let upstreamN2 = wrapper.string(forKey: "n2") ?? "nil"
let upstreamN4 = wrapper.string(forKey: "n4") ?? "nil"
let phaseTwoVault = SecureStorageVault(configuration: phaseTwo, bundleIdentifier: harnessBundle, isProtectedDataAvailable: { true })
check("F the configuration switches the deletion on", phaseTwoVault.configuration.deletesLegacyCopies)
var stepF = diagnostics(phaseTwoVault)
phaseTwoVault.queue.sync {
    check("F get copies n2 and returns the 0.13.0 value", describe(phaseTwoVault.loadValue(forKey: "n2")) == "resolve \(upstreamN2)" && currentValue(phaseTwoVault, "n2") == "decrypted(\(upstreamN2))")
}
check("F after the verified write both cap_sec copies of n2 are deleted", items(account: "n2", in: legacyService).isEmpty && groups("n2") == [appIdGroup])
var nowF = diagnostics(phaseTwoVault)
check("F duplicatesResolved counts two deletions, conflictingDuplicates the copy with another value", delta(stepF, nowF, "duplicatesResolved") == 2 && delta(stepF, nowF, "conflictingDuplicates") == 1 && delta(stepF, nowF, "migrated") == 1, "\(nowF)")
stepF = nowF
phaseTwoVault.queue.sync {
    check("F get copies bundle id only n3", describe(phaseTwoVault.loadValue(forKey: "n3")) == "resolve __secured_n3" && encrypted("n3"))
}
check("F and deletes its bundle id item", !KeychainWrapper.standard.hasValue(forKey: "n3"))
nowF = diagnostics(phaseTwoVault)
check("F one deletion counted", delta(stepF, nowF, "duplicatesResolved") == 1 && delta(stepF, nowF, "migrated") == 1, "\(nowF)")
stepF = nowF
phaseTwoVault.queue.sync {
    check("F set writes n5 and deletes its older copies", describe(phaseTwoVault.storeValue("__secured_n5_new", forKey: "n5")) == "resolve true" && items(account: "n5", in: legacyService).isEmpty && !KeychainWrapper.standard.hasValue(forKey: "n5") && currentValue(phaseTwoVault, "n5") == "decrypted(__secured_n5_new)")
}
nowF = diagnostics(phaseTwoVault)
check("F two deletions counted for the set, no migration", delta(stepF, nowF, "duplicatesResolved") == 2 && delta(stepF, nowF, "migrated") == 0, "\(nowF)")
stepF = nowF
phaseTwoVault.queue.sync {
    check("F the sweep resolves", describe(phaseTwoVault.migrateLegacyValues()) == "resolve -")
}
check("F the sweep deleted the copies phase 1 kept of n1 and n6, their cap_sec_v2 items are byte-identical", items(account: "n1", in: legacyService).isEmpty && !KeychainWrapper.standard.hasValue(forKey: "n1") && !KeychainWrapper.standard.hasValue(forKey: "n6") && !n1Current.isEmpty && snapshot(currentService, account: "n1") == n1Current && !n6Current.isEmpty && snapshot(currentService, account: "n6") == n6Current)
check("F the sweep copied n4 and deleted both its cap_sec copies", items(account: "n4", in: legacyService).isEmpty && phaseTwoVault.queue.sync { currentValue(phaseTwoVault, "n4") } == "decrypted(\(upstreamN4))")
check("F cap_sec is empty, the bundle id item of another key stays", items(in: legacyService).isEmpty && KeychainWrapper.standard.string(forKey: "foreign") == "__secured_foreign")
nowF = diagnostics(phaseTwoVault)
check("F sweep diagnostics: three copies of n1, one of n6 and two of n4 deleted, one migration, one conflict, nothing kept", delta(stepF, nowF, "duplicatesResolved") == 6 && delta(stepF, nowF, "migrated") == 1 && delta(stepF, nowF, "conflictingDuplicates") == 1 && counter(nowF, "legacyCopiesKept") == 0, "\(nowF)")
let everythingF = everything()
phaseTwoVault.queue.sync { _ = phaseTwoVault.migrateLegacyValues() }
check("F a second sweep changes nothing", everything() == everythingF)
let valuesF = ["n1": upstreamN1, "n2": upstreamN2, "n3": "__secured_n3", "n4": upstreamN4, "n5": "__secured_n5_new", "n6": "__secured_n6"]
check("F every value reads back", phaseTwoVault.queue.sync { valuesF.allSatisfy { describe(phaseTwoVault.loadValue(forKey: $0.key)) == "resolve \($0.value)" } })
_ = KeychainWrapper.standard.removeObject(forKey: "foreign")

print("--- G a lost cap_sec_v2 item")
cleanAll()
let lostTickerG = HarnessTicker()
let lostVaultG = SecureStorageVault(bundleIdentifier: harnessBundle, isProtectedDataAvailable: { true }, ticker: lostTickerG)
let lostLogG = EventLog()
check("G seed z1 in two groups", wrapperAppGroup.set("__secured_z_app", forKey: "z1", withAccessibility: .afterFirstUnlock) && wrapper.set("__secured_z_shared", forKey: "z1", withAccessibility: .afterFirstUnlock))
lostVaultG.queue.sync {
    check("G get copies z1 into cap_sec_v2", describe(lostVaultG.loadValue(forKey: "z1")).hasPrefix("resolve __secured_z_") && items(account: "z1").count == 1)
}
let legacyG = legacySnapshot()
lostVaultG.submitOperation(named: "set", key: "z1", run: { .locked }, lost: { lostVaultG.replaceLostValue("__secured_replaced", forKey: "z1") }, completion: { lostLogG.record("set \(describe($0))") })
lostVaultG.queue.sync {}
lostTickerG.fire(times: 2)
check("G a stuck set waits through two retries", lostLogG.events.isEmpty)
lostTickerG.fire()
check("G then the lost set replaces the cap_sec_v2 item with a fresh one", lostLogG.events == ["set resolve true"] && groups("z1") == [appIdGroup] && lostVaultG.queue.sync { describe(lostVaultG.loadValue(forKey: "z1")) } == "resolve __secured_replaced", "\(lostLogG.events)")
check("G the legacy copies are untouched", legacyG.count == 2 && legacySnapshot() == legacyG)
let diagnosticsG = diagnostics(lostVaultG)
check("G diagnostics: one lost item, nothing deleted", counter(diagnosticsG, "lostItems") == 1 && counter(diagnosticsG, "duplicatesResolved") == 0, "\(diagnosticsG)")

print("--- H explicit group not permitted")
cleanAll()
let fallbackTags = tags("harness.27")
let fallbackVault = makeVault(keyTag: fallbackTags.name, bundleIdentifier: "capacitor-secure-storage-plugin.not-permitted")
fallbackVault.queue.sync {
    check("H falls back to the default group", fallbackVault.resolveAccessGroup() == SecureStorageVault.AccessGroupMode(explicitGroup: nil, defaultGroup: sharedGroup), "\(String(describing: fallbackVault.resolveAccessGroup()))")
    check("H set lands in cap_sec_v2 in the default group", describe(fallbackVault.storeValue("__secured_fb", forKey: "fb1")) == "resolve true" && groups("fb1") == [sharedGroup], "\(groups("fb1"))")
    check("H get works", describe(fallbackVault.loadValue(forKey: "fb1")) == "resolve __secured_fb")
    check("H key created in the default group", keyAttributes(fallbackTags.secureEnclave).first?[kSecAttrAccessGroup as String] as? String == sharedGroup)
    check("H seed a 0.13.0 item in the app-ID group", wrapperAppGroup.set("__secured_fb2", forKey: "fb2", withAccessibility: .afterFirstUnlock))
    check("H get copies it into cap_sec_v2 in the default group", describe(fallbackVault.loadValue(forKey: "fb2")) == "resolve __secured_fb2" && groups("fb2") == [sharedGroup] && encrypted("fb2"), "\(groups("fb2"))")
    check("H the 0.13.0 item stays in the app-ID group", groups("fb2", in: legacyService) == [appIdGroup] && storedData("fb2", in: legacyService) == [Data("__secured_fb2".utf8)])
    check("H seed a 0.13.0 item for the sweep", wrapper.set("__secured_fb3", forKey: "fb3", withAccessibility: .afterFirstUnlock))
    check("H the sweep copies it into the default group", describe(fallbackVault.migrateLegacyValues()) == "resolve -" && groups("fb3") == [sharedGroup] && encrypted("fb3"), "\(groups("fb3"))")
    check("H keys lists every key once", listed(fallbackVault) == ["fb1", "fb2", "fb3"])
}
check("H diagnostics accessGroupMode default", diagnostics(fallbackVault)["accessGroupMode"] as? String == "default")
let noBundleVault = makeVault(bundleIdentifier: nil)
check("H no bundle id falls back too", noBundleVault.queue.sync { noBundleVault.resolveAccessGroup() } == SecureStorageVault.AccessGroupMode(explicitGroup: nil, defaultGroup: sharedGroup))
let explicitTags = tags("harness.27e")
let explicitVault = makeVault(keyTag: explicitTags.name)
explicitVault.queue.sync {
    check("H explicit mode", explicitVault.resolveAccessGroup() == SecureStorageVault.AccessGroupMode(explicitGroup: appIdGroup, defaultGroup: sharedGroup))
    check("H explicit set lands in cap_sec_v2 in the app-ID group", describe(explicitVault.storeValue("__secured_ex", forKey: "ex1")) == "resolve true" && groups("ex1") == [appIdGroup])
    check("H explicit key created in the app-ID group", keyAttributes(explicitTags.secureEnclave).first?[kSecAttrAccessGroup as String] as? String == appIdGroup)
}
let explicitDiagnostics = diagnostics(explicitVault)
check("H diagnostics accessGroupMode explicit, keyBackend secureEnclave", explicitDiagnostics["accessGroupMode"] as? String == "explicit" && explicitDiagnostics["keyBackend"] as? String == "secureEnclave", "\(explicitDiagnostics)")
check("H diagnostics has exactly the documented fields", Set(explicitDiagnostics.keys) == ["parked", "migrated", "duplicatesResolved", "lostItems", "decryptFailures", "plaintextFallbacks", "decryptRetries", "conflictingDuplicates", "legacyCopiesKept", "keyBackend", "accessGroupMode"], "\(explicitDiagnostics.keys.sorted())")
let explicitSameKey = makeVault(keyTag: fallbackTags.name)
explicitSameKey.queue.sync {
    check("H a later process in explicit mode still reads the cap_sec_v2 item of the default group", describe(explicitSameKey.loadValue(forKey: "fb1")) == "resolve __secured_fb")
    check("H its set writes the app-ID group, which wins from then on", describe(explicitSameKey.storeValue("__secured_fb_new", forKey: "fb1")) == "resolve true" && groups("fb1") == [appIdGroup, sharedGroup] && describe(explicitSameKey.loadValue(forKey: "fb1")) == "resolve __secured_fb_new")
}
check("H an existing key in another group is reused, not duplicated", keyCount(fallbackTags.secureEnclave) + keyCount(fallbackTags.software) == 1)

check("phase 1 vaults never deleted a legacy copy", [vault, upgrade, nextLaunch, wipe, bundleVault, earlier, lostVaultG, badVault, mixVault].allSatisfy { counter(diagnostics($0), "duplicatesResolved") == 0 })

cleanAll()
check("cleanup items", items().isEmpty && items(in: legacyService).isEmpty && allKeyCount() == 0)
print(failures == 0 ? "ALL PASS" : "FAILURES: \(failures)")
exit(failures == 0 ? 0 : 1)
