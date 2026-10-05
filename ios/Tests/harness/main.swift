import Foundation
import Security

let service = "cap_sec"
let upstreamService = "cap_sec_upstream"
let upstreamStandardService = "harness.standard.upstream"
// entitlements.plist mirrors the Skip Pay app: application-identifier <TEAM>.<bundle id> (the app-ID group, which the plugin
// now uses as its app-private group) and one keychain-access-groups entry that is the default group for writes without a
// group (the widget-shared group in the app).
let appIdGroup = "ABCDE12345.capacitor-secure-storage-plugin.harness"
let sharedGroup = appIdGroup + ".shared"
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
    dedicatedService: String = service,
    standardService: String = KeychainWrapper.standard.serviceName,
    keyTag: String = "capacitor-secure-storage-plugin.v1",
    bundleIdentifier: String? = harnessBundle,
    available: @escaping () -> Bool = { true }
) -> SecureStorageVault {
    return SecureStorageVault(
        configuration: SecureStorageVault.Configuration(accessibility: accessibility, encryptsValues: encrypts),
        dedicatedService: dedicatedService,
        standardService: standardService,
        keyTag: keyTag,
        bundleIdentifier: bundleIdentifier,
        isProtectedDataAvailable: available
    )
}

func items(account: String? = nil, in itemService: String = service) -> [[String: Any]] {
    var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: itemService, kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true, kSecReturnData as String: true]
    if let account = account { query[kSecAttrAccount as String] = Data(account.utf8) }
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    return status == errSecSuccess ? (result as? [[String: Any]] ?? []) : []
}

func accessible(_ account: String, in itemService: String = service) -> [String] {
    return items(account: account, in: itemService).map { $0[kSecAttrAccessible as String] as? String ?? "nil" }
}

func storedData(_ account: String, in itemService: String = service) -> [Data] {
    return items(account: account, in: itemService).compactMap { $0[kSecValueData as String] as? Data }
}

func modified(_ account: String, in itemService: String = service) -> [Date] {
    return items(account: account, in: itemService).compactMap { $0[kSecAttrModificationDate as String] as? Date }
}

func groups(_ account: String, in itemService: String = service) -> [String] {
    return items(account: account, in: itemService).map { $0[kSecAttrAccessGroup as String] as? String ?? "nil" }.sorted()
}

func marked(_ account: String, in itemService: String = service) -> [Bool] {
    return items(account: account, in: itemService).map { ($0[kSecAttrLabel as String] as? String) == marker }
}

func encrypted(_ account: String, in itemService: String = service) -> Bool {
    let data = storedData(account, in: itemService)
    return !data.isEmpty && data.allSatisfy { $0.starts(with: magic) }
}

/// Adds an item with the SwiftKeychainWrapper shape directly, optionally in a given group.
func addRaw(_ account: String, _ data: Data, group: String?, accessibility: CFString = kSecAttrAccessibleAfterFirstUnlock, in itemService: String = service, label: String? = nil) -> OSStatus {
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

func diagnostics(_ vault: SecureStorageVault) -> [String: Any] {
    return vault.queue.sync { vault.diagnostics() }
}

func counter(_ snapshot: [String: Any], _ name: String) -> Int {
    return snapshot[name] as? Int ?? -1
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
    for itemService in [service, upstreamService, upstreamStandardService, KeychainWrapper.standard.serviceName, otherService] { deleteService(itemService) }
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
    let read = vault.dedicated.readItem(key)
    return read.status == errSecSuccess ? read.data : nil
}

func encode(_ vault: SecureStorageVault, _ value: String) -> Data? {
    if case .encoded(let data) = vault.encodeValue(value) { return data }
    return nil
}

func write(_ vault: SecureStorageVault, _ key: String, _ data: Data, _ accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) -> OSStatus {
    return vault.dedicated.writeItem(key, data: data, accessibility: accessibility)
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

let legacy = KeychainWrapper(serviceName: service)
let legacyAppGroup = KeychainWrapper(serviceName: service, accessGroup: appIdGroup)
let legacyUpstream = KeychainWrapper(serviceName: upstreamService)
let legacyUpstreamStandard = KeychainWrapper(serviceName: upstreamStandardService)

cleanAll()
let vault = makeVault()
let plainVault = makeVault(.afterFirstUnlock, encrypts: false)

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
}

vault.queue.sync {
    print("--- 2 legacy default-group item")
    check("2 seed legacy AfterFirstUnlock", legacy.set("__secured_1234", forKey: "pin", withAccessibility: .afterFirstUnlock))
    check("2 seeded class ck", accessible("pin") == ["ck"])
    let stored = readData(vault, "pin")
    check("2 readItem finds legacy", stored != nil)
    check("2 decodeValue plaintext", stored.map { describe(vault.decodeValue($0)) } == "plaintext(__secured_1234)")
    let encoded = encode(vault, "__secured_1234")
    check("2 writeItem in place", encoded.map { write(vault, "pin", $0) } == errSecSuccess)
    let after = items(account: "pin")
    check("2 single item, class aku", after.count == 1 && accessible("pin") == ["aku"], "\(accessible("pin"))")
    check("2 data starts with MAGIC", (after.first?[kSecValueData as String] as? Data)?.starts(with: magic) == true)
    check("2 read+decode same string", readData(vault, "pin").map { describe(vault.decodeValue($0)) } == "decrypted(__secured_1234)")
    check("2 legacy wrapper can no longer read plaintext", legacy.string(forKey: "pin") != "__secured_1234")

    check("2b seed legacy pin2", legacy.set("__secured_5678", forKey: "pin2", withAccessibility: .afterFirstUnlock))
    check("2b loadValue resolves legacy plaintext", describe(vault.loadValue(forKey: "pin2")) == "resolve __secured_5678")
    check("2b migration ran inside the get", accessible("pin2") == ["aku"] && storedData("pin2").first?.starts(with: magic) == true, "\(accessible("pin2"))")

    check("2c seed legacy pin3", legacy.set("__secured_old", forKey: "pin3", withAccessibility: .afterFirstUnlock))
    check("2c storeValue over legacy class", describe(vault.storeValue("__secured_new", forKey: "pin3")) == "resolve true")
    check("2c pin3 single item aku + decrypts new", accessible("pin3") == ["aku"] && describe(vault.loadValue(forKey: "pin3")) == "resolve __secured_new")
}
vault.queue.sync {
    let pin2 = items(account: "pin2")
    check("2b write-back ran: aku + MAGIC", pin2.count == 1 && accessible("pin2") == ["aku"] && (pin2.first?[kSecValueData as String] as? Data)?.starts(with: magic) == true)
    check("2b loadValue after write-back", describe(vault.loadValue(forKey: "pin2")) == "resolve __secured_5678")
}

print("--- 2d get without encryption re-classes but keeps plaintext")
let plainStrictVault = makeVault(.whenUnlockedThisDeviceOnly, encrypts: false)
check("2d seed legacy pin4", legacy.set("__secured_p4", forKey: "pin4", withAccessibility: .afterFirstUnlock))
plainStrictVault.queue.sync {
    check("2d loadValue resolves", describe(plainStrictVault.loadValue(forKey: "pin4")) == "resolve __secured_p4")
}
settle(plainStrictVault)
check("2d item tightened to aku, still plaintext", accessible("pin4") == ["aku"] && storedData("pin4") == [Data("__secured_p4".utf8)], "\(accessible("pin4"))")

vault.queue.sync {
    print("--- 3 two access groups")
    check("3 seed app-ID group", legacyAppGroup.set("__secured_sig", forKey: "sig", withAccessibility: .afterFirstUnlock))
    check("3 seed default group duplicate", legacy.set("__secured_sig", forKey: "sig", withAccessibility: .afterFirstUnlock))
    let seeded = items(account: "sig")
    let groups = Set(seeded.compactMap { $0[kSecAttrAccessGroup as String] as? String })
    check("3 two items in two groups", seeded.count == 2 && groups.count == 2, "\(groups.sorted())")
    check("3 readItem finds one", readData(vault, "sig").map { describe(vault.decodeValue($0)) } == "plaintext(__secured_sig)")
    let keysBefore = vault.dedicated.listKeys().keys
    check("3 listKeys dedupes", keysBefore.filter { $0 == "sig" }.count == 1, "\(keysBefore)")
    let encoded = encode(vault, "__secured_sig")
    check("3 writeItem", encoded.map { write(vault, "sig", $0) } == errSecSuccess)
    let updated = items(account: "sig")
    check("3 both items updated to aku + MAGIC", updated.count == 2 && updated.allSatisfy { ($0[kSecAttrAccessible as String] as? String) == "aku" && ($0[kSecValueData as String] as? Data)?.starts(with: magic) == true }, "\(updated.map { "\($0[kSecAttrAccessGroup as String] ?? "?"):\($0[kSecAttrAccessible as String] ?? "?")" })")
    check("3 loadValue decrypts", describe(vault.loadValue(forKey: "sig")) == "resolve __secured_sig")
    check("3 deleteItem", vault.dedicated.deleteItem("sig") == errSecSuccess)
    check("3 both deleted", items(account: "sig").isEmpty)

    check("3b seed app-ID group sweep item", legacyAppGroup.set("__secured_dev", forKey: "dev", withAccessibility: .afterFirstUnlock))
    check("3b seed default group sweep item", legacy.set("__secured_dev", forKey: "dev", withAccessibility: .afterFirstUnlock))
    check("3b sweep resolves", describe(vault.migrateLegacyValues()) == "resolve -")
    let swept = items(account: "dev")
    check("3b sweep collapsed both copies into one encrypted aku item", swept.count == 1 && swept.allSatisfy { ($0[kSecAttrAccessible as String] as? String) == "aku" && ($0[kSecValueData as String] as? Data)?.starts(with: magic) == true })
    check("3b removeValue", describe(vault.removeValue(forKey: "dev")) == "resolve true" && items(account: "dev").isEmpty)
}
plainStrictVault.queue.sync {
    check("3c seed app-ID group plaintext item", legacyAppGroup.set("__secured_grp", forKey: "grp", withAccessibility: .afterFirstUnlock))
    check("3c seed default group plaintext item", legacy.set("__secured_grp", forKey: "grp", withAccessibility: .afterFirstUnlock))
    check("3c sweep resolves", describe(plainStrictVault.migrateLegacyValues()) == "resolve -")
    let swept = items(account: "grp")
    check("3c sweep without encryption collapses the copies, tightens, keeps plaintext", swept.count == 1 && swept.allSatisfy { ($0[kSecAttrAccessible as String] as? String) == "aku" && ($0[kSecValueData as String] as? Data) == Data("__secured_grp".utf8) }, "\(swept.map { "\($0[kSecAttrAccessible as String] ?? "?")" })")
    _ = plainStrictVault.dedicated.deleteItem("grp")
}

vault.queue.sync {
    print("--- 4 listKeys / deleteAll / remove / clear")
    deleteService(service)
    for key in ["a", "b", "c"] { _ = vault.storeValue("__secured_\(key)", forKey: key) }
    let listed = vault.dedicated.listKeys().keys
    check("4 listKeys exactly a,b,c", listed.sorted() == ["a", "b", "c"], "\(listed)")
    check("4 listStoredKeys outcome", describe(vault.listStoredKeys()).hasPrefix("resolve"))
    check("4 remove missing rejects", describe(vault.removeValue(forKey: "zzz")) == "reject Item with given key does not exist")
    check("4 remove existing", describe(vault.removeValue(forKey: "a")) == "resolve true")
    check("4 get removed rejects missing", describe(vault.loadValue(forKey: "a")) == "reject Item with given key does not exist")
    check("4 deleteAll", vault.dedicated.deleteAll() == errSecSuccess)
    let emptyList = vault.dedicated.listKeys()
    check("4 listKeys empty after deleteAll", emptyList.status == errSecSuccess && emptyList.keys.isEmpty)
    check("4 deleteAll on empty returns notFound", vault.dedicated.deleteAll() == errSecItemNotFound)
    _ = vault.storeValue("__secured_c", forKey: "c")
    KeychainWrapper.standard.set("__secured_std", forKey: "c")
    KeychainWrapper.standard.set("__secured_only", forKey: "stdOnly")
    check("4 removeAllValues resolves true", describe(vault.removeAllValues()) == "resolve true")
    check("4 clear removed dedicated and standard copy", items().isEmpty && !KeychainWrapper.standard.hasValue(forKey: "c"))
    check("4 clear keeps standard-only keys", KeychainWrapper.standard.string(forKey: "stdOnly") == "__secured_only")
    check("4 remove deletes a standard-only key", describe(vault.removeValue(forKey: "stdOnly")) == "resolve true" && !KeychainWrapper.standard.hasValue(forKey: "stdOnly"))
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
    check("5 non-UTF-8 plaintext in cap_sec is missing + UNREADABLE", write(vault, "badPlain", Data([0xFF, 0xFE, 0x00])) == errSecSuccess && describe(vault.loadValue(forKey: "badPlain")) == "reject Item with given key does not exist" && code(vault.loadValue(forKey: "badPlain")) == "UNREADABLE")
    check("5 set overwrites the undecryptable item", describe(vault.storeValue("__secured_fixed", forKey: "bad")) == "resolve true" && describe(vault.loadValue(forKey: "bad")) == "resolve __secured_fixed" && items(account: "bad").count == 1)
    _ = KeychainWrapper.standard.removeObject(forKey: "badStd")
    _ = vault.dedicated.deleteItem("bad")
    _ = vault.dedicated.deleteItem("badPlain")
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

print("--- 8 standard -> dedicated migration")
let migrationVault = makeVault()
check("8 default standard service matches KeychainWrapper.standard", SecureStorageVault().standard.service == KeychainWrapper.standard.serviceName, SecureStorageVault().standard.service)
check("8 seed standard", KeychainWrapper.standard.set("__secured_tok", forKey: "mobileToken"))
migrationVault.queue.sync {
    check("8 cap_sec empty before", items(account: "mobileToken").isEmpty)
    check("8 loadValue migrates", describe(migrationVault.loadValue(forKey: "mobileToken")) == "resolve __secured_tok")
    let migrated = items(account: "mobileToken")
    check("8 cap_sec has encrypted aku item", migrated.count == 1 && accessible("mobileToken") == ["aku"] && (migrated.first?[kSecValueData as String] as? Data)?.starts(with: magic) == true)
    check("8 standard item gone", !KeychainWrapper.standard.hasValue(forKey: "mobileToken"))
    check("8 second get reads dedicated", describe(migrationVault.loadValue(forKey: "mobileToken")) == "resolve __secured_tok")
    check("8 get missing in both rejects missing", describe(migrationVault.loadValue(forKey: "nothing")) == "reject Item with given key does not exist")
}
check("8p seed standard for plaintext vault", KeychainWrapper.standard.set("__secured_ptok", forKey: "plainToken"))
plainVault.queue.sync {
    check("8p loadValue migrates", describe(plainVault.loadValue(forKey: "plainToken")) == "resolve __secured_ptok")
    check("8p cap_sec has plaintext item, stricter legacy class ak kept", accessible("plainToken") == ["ak"] && storedData("plainToken") == [Data("__secured_ptok".utf8)], "\(accessible("plainToken"))")
    check("8p standard item gone", !KeychainWrapper.standard.hasValue(forKey: "plainToken"))
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

print("--- 13 parked legacy get + set: set wins over the migration write-back")
log.reset()
lockVault.queue.sync { _ = lockVault.dedicated.deleteItem("fifo2") }
check("13 seed legacy plaintext", legacy.set("__secured_legacy", forKey: "fifo2", withAccessibility: .afterFirstUnlock))
protectedFlag.write(false)
lockVault.submitOperation(named: "get", key: "fifo2", run: { lockVault.loadValue(forKey: "fifo2") }, completion: { log.record("get \(describe($0))") })
lockVault.submitOperation(named: "set", key: "fifo2", run: { lockVault.storeValue("__secured_fresh", forKey: "fifo2") }, completion: { log.record("set \(describe($0))") })
lockVault.queue.sync {}
protectedFlag.write(true)
lockVault.drainParkedOperations()
settle(lockVault)
check("13 get resolved legacy value, then set", log.events == ["get resolve __secured_legacy", "set resolve true"], "\(log.events)")
lockVault.queue.sync {
    check("13 final value is the set value, encrypted aku", accessible("fifo2") == ["aku"] && describe(lockVault.loadValue(forKey: "fifo2")) == "resolve __secured_fresh")
}

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
check("17a seed dedicated legacy s1", legacy.set("__secured_s1", forKey: "s1", withAccessibility: .afterFirstUnlock))
check("17a seed standard duplicate of s1", KeychainWrapper.standard.set("__secured_stale", forKey: "s1"))
check("17a seed standard-only s3", KeychainWrapper.standard.set("__secured_s3", forKey: "s3"))
var s2Before: [Data] = []
vault.queue.sync {
    check("17a seed encrypted s2", describe(vault.storeValue("__secured_s2", forKey: "s2", accessibility: .afterFirstUnlock)) == "resolve true")
    s2Before = storedData("s2")
    check("17a sweep resolves", describe(vault.migrateLegacyValues()) == "resolve -")
    check("17a legacy s1 encrypted with the default class", accessible("s1") == ["aku"] && storedData("s1").first?.starts(with: magic) == true && describe(vault.loadValue(forKey: "s1")) == "resolve __secured_s1", "\(accessible("s1"))")
    check("17a encrypted s2 with a per-call ck class left alone", storedData("s2") == s2Before && accessible("s2") == ["ck"], "\(accessible("s2"))")
    check("17a standard-only s3 not swept", items(account: "s3").isEmpty && KeychainWrapper.standard.string(forKey: "s3") == "__secured_s3")
    check("17a standard duplicate of s1 removed after the verified write", !KeychainWrapper.standard.hasValue(forKey: "s1"))
    let snapshot = items().map { $0[kSecValueData as String] as? Data }
    check("17b second sweep resolves", describe(vault.migrateLegacyValues()) == "resolve -")
    check("17b second sweep rewrites nothing", items().map { $0[kSecValueData as String] as? Data } == snapshot && snapshot.count == 2, "\(snapshot.count)")
    check("17a get moves standard-only s3 lazily", describe(vault.loadValue(forKey: "s3")) == "resolve __secured_s3" && accessible("s3") == ["aku"] && storedData("s3").first?.starts(with: magic) == true && !KeychainWrapper.standard.hasValue(forKey: "s3"))
}
cleanAll()

check("17c seed plaintext ck r1", legacy.set("__secured_r1", forKey: "r1", withAccessibility: .afterFirstUnlock))
check("17c seed plaintext aku r2", legacy.set("__secured_r2", forKey: "r2", withAccessibility: .whenUnlockedThisDeviceOnly))
vault.queue.sync {
    check("17c seed encrypted ck r3", encode(vault, "__secured_r3").map { write(vault, "r3", $0, kSecAttrAccessibleAfterFirstUnlock) } == errSecSuccess)
}
check("17d seed upstream-style ck item", legacyUpstream.set("__secured_u1", forKey: "u1", withAccessibility: .afterFirstUnlock))
check("17d seed upstream standard item", legacyUpstreamStandard.set("__secured_u2", forKey: "u2"))
let r1Seeded = modified("r1")
let r2Seeded = modified("r2")
let r3Before = storedData("r3")
let u1Seeded = modified("u1", in: upstreamService)
Thread.sleep(forTimeInterval: 1.2)
plainStrictVault.queue.sync {
    check("17c sweep without encryption resolves", describe(plainStrictVault.migrateLegacyValues()) == "resolve -")
    check("17c legacy plaintext r1 tightened to aku, still plaintext", accessible("r1") == ["aku"] && storedData("r1") == [Data("__secured_r1".utf8)] && modified("r1") != r1Seeded && !r1Seeded.isEmpty, "\(accessible("r1"))")
    check("17c r2 moved into the app-private group, aku and plaintext kept", accessible("r2") == ["aku"] && groups("r2") == [appIdGroup] && storedData("r2") == [Data("__secured_r2".utf8)] && !r2Seeded.isEmpty, "\(groups("r2"))")
    check("17c encrypted ck r3 written by this version keeps its class and bytes", accessible("r3") == ["ck"] && storedData("r3") == r3Before)
    let r1Swept = modified("r1")
    check("17c new write gets the configured default class", describe(plainStrictVault.storeValue("__secured_r1b", forKey: "r1")) == "resolve true" && accessible("r1") == ["aku"] && storedData("r1") == [Data("__secured_r1b".utf8)])
    check("17c modification date detects the rewrite", modified("r1") != r1Swept)
}
let upstreamVault = makeVault(.afterFirstUnlock, encrypts: false, dedicatedService: upstreamService, standardService: upstreamStandardService)
upstreamVault.queue.sync {
    check("17d sweep with upstream defaults resolves", describe(upstreamVault.migrateLegacyValues()) == "resolve -")
    check("17d upstream item moved into the app-private group, ck and plaintext kept", modified("u1", in: upstreamService) != u1Seeded && !u1Seeded.isEmpty && accessible("u1", in: upstreamService) == ["ck"] && groups("u1", in: upstreamService) == [appIdGroup] && storedData("u1", in: upstreamService) == [Data("__secured_u1".utf8)], "\(groups("u1", in: upstreamService))")
    check("17d upstream standard item not swept", items(account: "u2", in: upstreamService).isEmpty && legacyUpstreamStandard.string(forKey: "u2") == "__secured_u2")
    check("17d get moves the standard item as plaintext, stricter legacy class ak kept", describe(upstreamVault.loadValue(forKey: "u2")) == "resolve __secured_u2" && accessible("u2", in: upstreamService) == ["ak"] && storedData("u2", in: upstreamService) == [Data("__secured_u2".utf8)] && items(account: "u2", in: upstreamStandardService).isEmpty)
}
cleanAll()

let sweepFlag = Flag(false)
let sweepVault = makeVault(available: { sweepFlag.read() })
check("17e seed legacy l1", legacy.set("__secured_l1", forKey: "l1", withAccessibility: .afterFirstUnlock))
sweepVault.submitOperation(named: "sweep", key: "*", run: { sweepVault.migrateLegacyValues() })
settle(sweepVault)
check("17e sweep parked while protected data is unavailable", accessible("l1") == ["ck"] && storedData("l1") == [Data("__secured_l1".utf8)])
sweepFlag.write(true)
sweepVault.drainParkedOperations()
settle(sweepVault)
check("17e sweep ran after drain", accessible("l1") == ["aku"] && storedData("l1").first?.starts(with: magic) == true)
cleanAll()

print("--- 18 gate bypass with afterFirstUnlock default")
let bypassVault = makeVault(.afterFirstUnlock, available: { false })
log.reset()
bypassVault.submitOperation(named: "set", key: "b1", run: { bypassVault.storeValue("__secured_b1", forKey: "b1") }, completion: { log.record("set \(describe($0))") })
bypassVault.submitOperation(named: "get", key: "b1", run: { bypassVault.loadValue(forKey: "b1") }, completion: { log.record("get \(describe($0))") })
settle(bypassVault)
check("18 set and get run while protected data is unavailable", log.events == ["set resolve true", "get resolve __secured_b1"], "\(log.events)")
check("18 item stored encrypted with ck", accessible("b1") == ["ck"] && storedData("b1").first?.starts(with: magic) == true)

print("--- 19 plaintext round trip with upstream defaults")
cleanAll()
plainVault.queue.sync {
    check("19 storeValue resolves", describe(plainVault.storeValue("__secured_plain", forKey: "p1")) == "resolve true")
    check("19 stored bytes are the UTF-8 plaintext", storedData("p1") == [Data("__secured_plain".utf8)])
    check("19 class ck", accessible("p1") == ["ck"], "\(accessible("p1"))")
    check("19 loadValue resolves", describe(plainVault.loadValue(forKey: "p1")) == "resolve __secured_plain")
    check("19 SwiftKeychainWrapper reads the item", legacy.string(forKey: "p1") == "__secured_plain")
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
check("21 seed legacy aku item", legacy.set("__secured_keep1", forKey: "k1", withAccessibility: .whenUnlockedThisDeviceOnly))
check("21 seed legacy akpu item", legacy.set("__secured_keep2", forKey: "k2", withAccessibility: .whenPasscodeSetThisDeviceOnly))
check("21 seed standard aku item", KeychainWrapper.standard.set("__secured_keep3", forKey: "k3", withAccessibility: .whenUnlockedThisDeviceOnly))
relaxedEncryptingVault.queue.sync {
    check("21 sweep resolves", describe(relaxedEncryptingVault.migrateLegacyValues()) == "resolve -")
    check("21 sweep encrypts but keeps the stricter aku", accessible("k1") == ["aku"] && storedData("k1").first?.starts(with: magic) == true, "\(accessible("k1"))")
    check("21 sweep keeps akpu", accessible("k2") == ["akpu"] && storedData("k2").first?.starts(with: magic) == true, "\(accessible("k2"))")
    check("21 bundle id move keeps aku", describe(relaxedEncryptingVault.loadValue(forKey: "k3")) == "resolve __secured_keep3" && accessible("k3") == ["aku"] && storedData("k3").first?.starts(with: magic) == true, "\(accessible("k3"))")
    check("21 plain set still uses the configured class", describe(relaxedEncryptingVault.storeValue("__secured_keep1b", forKey: "k1")) == "resolve true" && accessible("k1") == ["ck"])
}
let lazyKeepVault = makeVault(.afterFirstUnlock)
check("21 seed legacy akpu item for get", legacy.set("__secured_keep4", forKey: "k4", withAccessibility: .whenPasscodeSetThisDeviceOnly))
lazyKeepVault.queue.sync {
    check("21 get resolves legacy akpu", describe(lazyKeepVault.loadValue(forKey: "k4")) == "resolve __secured_keep4")
}
settle(lazyKeepVault)
check("21 lazy re-encrypt on get keeps akpu", accessible("k4") == ["akpu"] && storedData("k4").first?.starts(with: magic) == true, "\(accessible("k4"))")
let mixedVault = makeVault(.afterFirstUnlockThisDeviceOnly)
check("21 seed legacy ak item", legacy.set("__secured_mix", forKey: "k5", withAccessibility: .whenUnlocked))
mixedVault.queue.sync {
    check("21 sweep combines ak and cku into aku", describe(mixedVault.migrateLegacyValues()) == "resolve -" && accessible("k5") == ["aku"], "\(accessible("k5"))")
}
let strictVault = makeVault(.whenUnlockedThisDeviceOnly)
check("21 seed legacy ck item", legacy.set("__secured_tight", forKey: "k6", withAccessibility: .afterFirstUnlock))
strictVault.queue.sync {
    check("21 sweep tightens ck to aku", describe(strictVault.migrateLegacyValues()) == "resolve -" && accessible("k6") == ["aku"] && storedData("k6").first?.starts(with: magic) == true, "\(accessible("k6"))")
}

print("--- 22 copies in two groups with different modification dates")
cleanAll()
let dupVault = makeVault()
check("22a seed stale copy in the app-ID group (written before the entitlement change)", legacyAppGroup.set("__secured_old", forKey: "d1", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("22a seed newer copy in the shared group (first add after the change)", legacy.set("__secured_new", forKey: "d1", withAccessibility: .afterFirstUnlock))
check("22a two copies", groups("d1") == [appIdGroup, sharedGroup], "\(groups("d1"))")
// What 0.13.0 returned: SwiftKeychainWrapper without a group, limit one, read before the vault touches the key.
let upstreamD1 = legacy.string(forKey: "d1") ?? "nil"
dupVault.queue.sync {
    check("22a get returns the copy upstream 0.13.0 read, not the newest one", describe(dupVault.loadValue(forKey: "d1")) == "resolve \(upstreamD1)", upstreamD1)
    check("22a one copy left: app-ID group, encrypted, aku, marked", groups("d1") == [appIdGroup] && encrypted("d1") && accessible("d1") == ["aku"] && marked("d1") == [true], "\(groups("d1")) \(accessible("d1"))")
    check("22a next get returns the same value", describe(dupVault.loadValue(forKey: "d1")) == "resolve \(upstreamD1)")
}
check("22b seed older copy in the shared group", legacy.set("__secured_old2", forKey: "d2", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("22b seed newer copy in the app-ID group", legacyAppGroup.set("__secured_new2", forKey: "d2", withAccessibility: .afterFirstUnlock))
let upstreamD2 = legacy.string(forKey: "d2") ?? "nil"
let conflictsBefore22 = counter(diagnostics(dupVault), "conflictingDuplicates")
dupVault.queue.sync {
    check("22b get returns the copy upstream 0.13.0 read", describe(dupVault.loadValue(forKey: "d2")) == "resolve \(upstreamD2)", upstreamD2)
    check("22b other copy deleted after the verified write", groups("d2") == [appIdGroup] && encrypted("d2"), "\(groups("d2"))")
    check("22b next get returns the same value", describe(dupVault.loadValue(forKey: "d2")) == "resolve \(upstreamD2)")
}
check("22b the copy with the other value counts as a conflicting duplicate", counter(diagnostics(dupVault), "conflictingDuplicates") - conflictsBefore22 == 1)
check("22ab the upstream read differs from the newest copy at least once, so the rule is exercised", upstreamD1 == "__secured_old" || upstreamD2 == "__secured_old2", "\(upstreamD1) \(upstreamD2)")
check("22c seed stale app-ID copy", legacyAppGroup.set("__secured_s_old", forKey: "d3", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("22c seed newer shared copy", legacy.set("__secured_s_new", forKey: "d3", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("22c seed an even newer bundle id copy", KeychainWrapper.standard.set("__secured_s_std", forKey: "d3"))
let upstreamD3 = legacy.string(forKey: "d3") ?? "nil"
let before22 = diagnostics(dupVault)
dupVault.queue.sync {
    check("22c sweep resolves", describe(dupVault.migrateLegacyValues()) == "resolve -")
    check("22c sweep kept the cap_sec copy upstream read, the bundle id copy ranks below cap_sec", describe(dupVault.loadValue(forKey: "d3")) == "resolve \(upstreamD3)", upstreamD3)
}
check("22c one copy left and the bundle id copy is gone", groups("d3") == [appIdGroup] && !KeychainWrapper.standard.hasValue(forKey: "d3"), "\(groups("d3"))")
let after22 = diagnostics(dupVault)
check("22c diagnostics: one migration, two duplicates resolved, both with another value", counter(after22, "migrated") - counter(before22, "migrated") == 1 && counter(after22, "duplicatesResolved") - counter(before22, "duplicatesResolved") == 2 && counter(after22, "conflictingDuplicates") - counter(before22, "conflictingDuplicates") == 2, "\(before22) \(after22)")
check("22d seed two copies of d4", legacyAppGroup.set("__secured_a", forKey: "d4", withAccessibility: .afterFirstUnlock) && legacy.set("__secured_b", forKey: "d4", withAccessibility: .afterFirstUnlock))
dupVault.queue.sync {
    check("22d set over two copies leaves one fresh copy", describe(dupVault.storeValue("__secured_c", forKey: "d4")) == "resolve true" && groups("d4") == [appIdGroup] && describe(dupVault.loadValue(forKey: "d4")) == "resolve __secured_c", "\(groups("d4"))")
    check("22e second sweep rewrites nothing", { () -> Bool in
        let snapshot = items().map { "\($0[kSecAttrAccessGroup as String] ?? "")|\(($0[kSecAttrModificationDate as String] as? Date)?.timeIntervalSince1970 ?? 0)" }.sorted()
        _ = dupVault.migrateLegacyValues()
        return snapshot == items().map { "\($0[kSecAttrAccessGroup as String] ?? "")|\(($0[kSecAttrModificationDate as String] as? Date)?.timeIntervalSince1970 ?? 0)" }.sorted() && snapshot.count == 4
    }())
}
check("22f the 0.13.0 query shape (no group, account + generic) still finds migrated items", legacy.hasValue(forKey: "d1") && legacy.hasValue(forKey: "d3") && legacy.hasValue(forKey: "d4"))
dupVault.queue.sync {
    check("22g seed a copy written by this version", describe(dupVault.storeValue("__secured_marked", forKey: "d5")) == "resolve true" && marked("d5") == [true])
}
Thread.sleep(forTimeInterval: 0.05)
check("22g seed a newer unmarked copy in the shared group", legacy.set("__secured_unmarked", forKey: "d5", withAccessibility: .afterFirstUnlock) && groups("d5") == [appIdGroup, sharedGroup], "\(groups("d5"))")
dupVault.queue.sync {
    check("22g a copy written by this version beats a newer unmarked one", describe(dupVault.loadValue(forKey: "d5")) == "resolve __secured_marked" && groups("d5") == [appIdGroup], "\(groups("d5"))")
}

print("--- 23 legacy bundle id service item")
check("23a seed bundle id item", KeychainWrapper.standard.set("__secured_std1", forKey: "std1"))
dupVault.queue.sync {
    check("23a get moves it", describe(dupVault.loadValue(forKey: "std1")) == "resolve __secured_std1")
    check("23a now in cap_sec, app-ID group, encrypted, aku", groups("std1") == [appIdGroup] && encrypted("std1") && accessible("std1") == ["aku"], "\(groups("std1"))")
}
check("23a bundle id copy deleted after the verified write", !KeychainWrapper.standard.hasValue(forKey: "std1"))
check("23b seed cap_sec copy", legacy.set("__secured_cap", forKey: "std2", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("23b seed newer bundle id copy", KeychainWrapper.standard.set("__secured_newer_std", forKey: "std2"))
dupVault.queue.sync {
    check("23b cap_sec copy wins over a newer bundle id copy", describe(dupVault.loadValue(forKey: "std2")) == "resolve __secured_cap")
}
check("23b get leaves the bundle id duplicate to the sweep", KeychainWrapper.standard.hasValue(forKey: "std2"))
dupVault.queue.sync { _ = dupVault.migrateLegacyValues() }
check("23b sweep removes the bundle id duplicate", !KeychainWrapper.standard.hasValue(forKey: "std2") && groups("std2") == [appIdGroup])
check("23c bundle id items of other keys stay", KeychainWrapper.standard.set("__secured_foreign", forKey: "foreign") && { dupVault.queue.sync { _ = dupVault.migrateLegacyValues() }; return KeychainWrapper.standard.string(forKey: "foreign") == "__secured_foreign" }())
_ = KeychainWrapper.standard.removeObject(forKey: "foreign")

print("--- 24 mixed plaintext and encrypted items")
cleanAll()
let mixVault = makeVault()
check("24 seed plaintext ck in the shared group", legacy.set("__secured_m1", forKey: "m1", withAccessibility: .afterFirstUnlock))
check("24 seed plaintext aku in the app-ID group", legacyAppGroup.set("__secured_m2", forKey: "m2", withAccessibility: .whenUnlockedThisDeviceOnly))
var mixBefore: [String: [Data]] = [:]
mixVault.queue.sync {
    check("24 seed encrypted aku via set", describe(mixVault.storeValue("__secured_m3", forKey: "m3")) == "resolve true")
    check("24 seed encrypted per-call ck via set", describe(mixVault.storeValue("__secured_m4", forKey: "m4", accessibility: .afterFirstUnlock)) == "resolve true")
    check("24 seed encrypted ck in the shared group", encode(mixVault, "__secured_m5").map { write(mixVault, "m5", $0, kSecAttrAccessibleAfterFirstUnlock) } == errSecSuccess && groups("m5") == [sharedGroup])
    for key in ["m3", "m4", "m5"] { mixBefore[key] = storedData(key) }
    check("24 sweep resolves", describe(mixVault.migrateLegacyValues()) == "resolve -")
}
check("24 every item in the app-ID group", ["m1", "m2", "m3", "m4", "m5"].allSatisfy { groups($0) == [appIdGroup] }, "\(["m1", "m2", "m3", "m4", "m5"].map { groups($0) })")
check("24 every item encrypted", ["m1", "m2", "m3", "m4", "m5"].allSatisfy { encrypted($0) })
check("24 legacy plaintext tightened to aku", accessible("m1") == ["aku"] && accessible("m2") == ["aku"])
check("24 items written by this version keep their class and bytes", accessible("m3") == ["aku"] && accessible("m4") == ["ck"] && accessible("m5") == ["ck"] && ["m3", "m4", "m5"].allSatisfy { storedData($0) == mixBefore[$0] }, "\(accessible("m4")) \(accessible("m5"))")
mixVault.queue.sync {
    check("24 keys lists each key once", { () -> Bool in
        guard case .resolve(let data) = mixVault.listStoredKeys(), let keys = data["value"] as? [String] else { return false }
        return keys.sorted() == ["m1", "m2", "m3", "m4", "m5"]
    }())
    check("24 every value reads back", ["m1", "m2", "m3", "m4", "m5"].allSatisfy { describe(mixVault.loadValue(forKey: $0)) == "resolve __secured_\($0)" })
}

print("--- 25 ciphertext that cannot be decrypted")
cleanAll()
let badVault = makeVault()
check("25 seed older plaintext copy in the shared group", legacy.set("__secured_older", forKey: "u1", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("25 seed newer undecryptable copy in the app-ID group, written by this version", addRaw("u1", magic + Data(repeating: 0x5A, count: 97), group: appIdGroup, accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, label: marker) == errSecSuccess)
let before25 = diagnostics(badVault)
let garbage25 = magic + Data(repeating: 0x5A, count: 97)
func copy(_ account: String, in group: String) -> [String: Any]? {
    return items(account: account).first { ($0[kSecAttrAccessGroup as String] as? String) == group }
}
func copyData(_ account: String, in group: String) -> Data? {
    return copy(account, in: group)?[kSecValueData as String] as? Data
}
func copyClass(_ account: String, in group: String) -> String? {
    return copy(account, in: group)?[kSecAttrAccessible as String] as? String
}
func copyMarked(_ account: String, in group: String) -> Bool {
    return copy(account, in: group)?[kSecAttrLabel as String] as? String == marker
}
badVault.queue.sync {
    let read = badVault.loadValue(forKey: "u1")
    check("25 get reports missing with code UNREADABLE", describe(read) == "reject Item with given key does not exist" && code(read) == "UNREADABLE", "\(describe(read)) \(code(read))")
    check("25 nothing deleted, no stale value resurrected", groups("u1") == [appIdGroup, sharedGroup])
    check("25 the older plaintext copy is encrypted and tightened in place: shared group, aku, still unmarked", copyData("u1", in: sharedGroup)?.starts(with: magic) == true && copyClass("u1", in: sharedGroup) == "aku" && !copyMarked("u1", in: sharedGroup), "\(copyClass("u1", in: sharedGroup) ?? "nil")")
    check("25 the undecryptable copy is untouched", copyData("u1", in: appIdGroup) == garbage25 && copyMarked("u1", in: appIdGroup))
    let again = badVault.loadValue(forKey: "u1")
    check("25 the next get is still UNREADABLE, the rewritten older copy does not win", code(again) == "UNREADABLE", describe(again))
    check("25 sweep leaves both copies", describe(badVault.migrateLegacyValues()) == "resolve -" && groups("u1") == [appIdGroup, sharedGroup])
    check("25 set overwrites, one copy left", describe(badVault.storeValue("__secured_fresh", forKey: "u1")) == "resolve true" && describe(badVault.loadValue(forKey: "u1")) == "resolve __secured_fresh" && groups("u1") == [appIdGroup], "\(groups("u1"))")
}
check("25 decryptFailures counted for two gets and the sweep", counter(diagnostics(badVault), "decryptFailures") - counter(before25, "decryptFailures") == 3, "\(diagnostics(badVault))")
let noKeyTags = tags("harness.25.nokey")
let noKeyVault = makeVault(keyTag: noKeyTags.name)
noKeyVault.queue.sync {
    let read = noKeyVault.loadValue(forKey: "u1")
    check("25 ciphertext of a key that does not exist is UNREADABLE", describe(read) == "reject Item with given key does not exist" && code(read) == "UNREADABLE", describe(read))
    check("25 decrypting never creates a key", keyCount(noKeyTags.secureEnclave) + keyCount(noKeyTags.software) == 0)
}
check("25b seed older plaintext copy in the shared group", legacy.set("__secured_older_b", forKey: "u2", withAccessibility: .afterFirstUnlock))
Thread.sleep(forTimeInterval: 0.05)
check("25b seed an undecryptable copy without the label in the app-ID group", addRaw("u2", garbage25, group: appIdGroup, accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly) == errSecSuccess)
check("25b upstream 0.13.0 reads the undecryptable copy", legacy.data(forKey: "u2") == garbage25)
badVault.queue.sync {
    check("25b get is UNREADABLE", code(badVault.loadValue(forKey: "u2")) == "UNREADABLE")
    check("25b the older unlabelled copy is encrypted and tightened in place", copyData("u2", in: sharedGroup)?.starts(with: magic) == true && copyClass("u2", in: sharedGroup) == "aku" && !copyMarked("u2", in: sharedGroup))
    check("25b the next get still settles on the copy upstream read", code(badVault.loadValue(forKey: "u2")) == "UNREADABLE" && legacy.data(forKey: "u2") == garbage25)
}
check("25c seed an older copy that is not UTF-8 in the shared group", addRaw("u3", Data([0xFF, 0xFE, 0x00]), group: sharedGroup) == errSecSuccess)
Thread.sleep(forTimeInterval: 0.05)
check("25c seed a newer undecryptable copy written by this version", addRaw("u3", garbage25, group: appIdGroup, accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, label: marker) == errSecSuccess)
badVault.queue.sync {
    check("25c get is UNREADABLE", code(badVault.loadValue(forKey: "u3")) == "UNREADABLE")
    check("25c an older copy that is not readable plaintext stays as it is", copyData("u3", in: sharedGroup) == Data([0xFF, 0xFE, 0x00]) && copyClass("u3", in: sharedGroup) == "ck")
    check("25c the next set removes it", describe(badVault.storeValue("__secured_u3", forKey: "u3")) == "resolve true" && groups("u3") == [appIdGroup])
}

print("--- 26 clear and remove only touch cap_sec")
cleanAll()
let clearTags = tags("harness.26")
let clearVault = makeVault(keyTag: clearTags.name)
check("26 seed item under another service", addRaw("o1", Data("__secured_other".utf8), group: nil, in: otherService) == errSecSuccess)
check("26 seed item without a service (fingerprint-aio __aio_key)", SecItemAdd([kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: noServiceAccount, kSecValueData as String: Data("__secured_aio".utf8)] as CFDictionary, nil) == errSecSuccess && noServiceItemExists())
check("26 seed cap_sec item in the shared group", legacy.set("__secured_c3", forKey: "c3", withAccessibility: .afterFirstUnlock))
clearVault.queue.sync {
    check("26 seed cap_sec items", describe(clearVault.storeValue("__secured_c1", forKey: "c1")) == "resolve true" && describe(clearVault.storeValue("__secured_c2", forKey: "c2")) == "resolve true")
    check("26 keys ignores other services", { () -> Bool in
        guard case .resolve(let data) = clearVault.listStoredKeys(), let keys = data["value"] as? [String] else { return false }
        return keys.sorted() == ["c1", "c2", "c3"]
    }())
    check("26 remove of a missing key rejects NOT_FOUND", code(clearVault.removeValue(forKey: "o1")) == "NOT_FOUND" && items(account: "o1", in: otherService).count == 1)
    check("26 clear resolves", describe(clearVault.removeAllValues()) == "resolve true")
}
check("26 cap_sec empty in every group", items().isEmpty)
check("26 other service item survived", storedData("o1", in: otherService) == [Data("__secured_other".utf8)])
check("26 item without a service survived", noServiceItemExists())
check("26 Secure Enclave key survived", keyCount(clearTags.secureEnclave) + keyCount(clearTags.software) == 1)
check("26 no probe items left behind", items(in: service + ".probe").isEmpty)

print("--- 27 explicit group not permitted")
cleanAll()
let fallbackTags = tags("harness.27")
let fallbackVault = makeVault(keyTag: fallbackTags.name, bundleIdentifier: "capacitor-secure-storage-plugin.not-permitted")
fallbackVault.queue.sync {
    check("27 falls back to the default group", fallbackVault.resolveAccessGroup() == SecureStorageVault.AccessGroupMode(explicitGroup: nil, defaultGroup: sharedGroup), "\(String(describing: fallbackVault.resolveAccessGroup()))")
    check("27 set lands in the default group", describe(fallbackVault.storeValue("__secured_fb", forKey: "fb1")) == "resolve true" && groups("fb1") == [sharedGroup], "\(groups("fb1"))")
    check("27 get works", describe(fallbackVault.loadValue(forKey: "fb1")) == "resolve __secured_fb")
    check("27 key created in the default group", keyAttributes(fallbackTags.secureEnclave).first?[kSecAttrAccessGroup as String] as? String == sharedGroup)
}
check("27 diagnostics accessGroupMode default", diagnostics(fallbackVault)["accessGroupMode"] as? String == "default")
let noBundleVault = makeVault(bundleIdentifier: nil)
check("27 no bundle id falls back too", noBundleVault.queue.sync { noBundleVault.resolveAccessGroup() } == SecureStorageVault.AccessGroupMode(explicitGroup: nil, defaultGroup: sharedGroup))
let explicitTags = tags("harness.27e")
let explicitVault = makeVault(keyTag: explicitTags.name)
explicitVault.queue.sync {
    check("27 explicit mode", explicitVault.resolveAccessGroup() == SecureStorageVault.AccessGroupMode(explicitGroup: appIdGroup, defaultGroup: sharedGroup))
    check("27 explicit set lands in the app-ID group", describe(explicitVault.storeValue("__secured_ex", forKey: "ex1")) == "resolve true" && groups("ex1") == [appIdGroup])
    check("27 explicit key created in the app-ID group", keyAttributes(explicitTags.secureEnclave).first?[kSecAttrAccessGroup as String] as? String == appIdGroup)
}
let explicitDiagnostics = diagnostics(explicitVault)
check("27 diagnostics accessGroupMode explicit, keyBackend secureEnclave", explicitDiagnostics["accessGroupMode"] as? String == "explicit" && explicitDiagnostics["keyBackend"] as? String == "secureEnclave", "\(explicitDiagnostics)")
check("27 diagnostics has exactly the documented fields", Set(explicitDiagnostics.keys) == ["parked", "migrated", "duplicatesResolved", "lostItems", "decryptFailures", "plaintextFallbacks", "decryptRetries", "conflictingDuplicates", "keyBackend", "accessGroupMode"], "\(explicitDiagnostics.keys.sorted())")
fallbackVault.queue.sync {
    check("27 fallback mode moves an app-ID item into the default group", addRaw("fb2", Data("__secured_fb2".utf8), group: appIdGroup) == errSecSuccess && describe(fallbackVault.loadValue(forKey: "fb2")) == "resolve __secured_fb2" && groups("fb2") == [sharedGroup], "\(groups("fb2"))")
}
check("27 an existing key in another group is reused, not duplicated", { () -> Bool in
    let reuse = makeVault(keyTag: fallbackTags.name)
    return reuse.queue.sync { encode(reuse, "__secured_reuse").map { describe(reuse.decodeValue($0)) } == "decrypted(__secured_reuse)" } && keyCount(fallbackTags.secureEnclave) + keyCount(fallbackTags.software) == 1
}())

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
            let seeded = legacy.set("__secured_n", forKey: key, withAccessibility: wrapperClass)
            let matrixVault = makeVault(configured, encrypts: encrypts)
            matrixVault.queue.sync {
                if encrypts {
                    _ = matrixVault.loadValue(forKey: key)
                } else {
                    _ = matrixVault.migrateLegacyValues()
                }
            }
            let encodingOK = encrypts ? encrypted(key) : storedData(key) == [Data("__secured_n".utf8)]
            check("28 \(encrypts ? "get" : "sweep") \(existing.rawValue) + \(configured.rawValue) -> \(expected)", seeded && accessible(key) == [expected] && groups(key) == [appIdGroup] && encodingOK, "\(accessible(key)) \(groups(key))")
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
    check("28 a per-call \(perCall.rawValue) written by this version survives the sweep under a stricter default", accessible(key) == [perCall.attribute as String], "\(accessible(key))")
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
    check("30 seed legacy ck", legacy.set("__secured_pf3", forKey: "pf3", withAccessibility: .afterFirstUnlock))
    check("30 migration falls back too: plaintext, aku, app-ID group", describe(plainFallbackVault.loadValue(forKey: "pf3")) == "resolve __secured_pf3" && storedData("pf3") == [Data("__secured_pf3".utf8)] && accessible("pf3") == ["aku"] && groups("pf3") == [appIdGroup], "\(accessible("pf3")) \(groups("pf3"))")
    plainFallbackVault.simulatesEncryptionFailure = false
    check("30 sweep encrypts the fallback items once encryption works, classes kept", describe(plainFallbackVault.migrateLegacyValues()) == "resolve -" && ["pf1", "pf2", "pf3"].allSatisfy { encrypted($0) } && accessible("pf1") == ["aku"] && accessible("pf2") == ["akpu"] && accessible("pf3") == ["aku"])
    check("30 values still read back", ["pf1": "__secured_pf", "pf2": "__secured_pf2", "pf3": "__secured_pf3"].allSatisfy { describe(plainFallbackVault.loadValue(forKey: $0.key)) == "resolve \($0.value)" })
}
check("30 diagnostics count three plaintext fallbacks", counter(diagnostics(plainFallbackVault), "plaintextFallbacks") == 3, "\(diagnostics(plainFallbackVault))")

print("--- 31 lost items with the real keychain and unlock probe")
cleanAll()
let lostTicker = HarnessTicker()
let lostVault = SecureStorageVault(bundleIdentifier: harnessBundle, isProtectedDataAvailable: { true }, ticker: lostTicker)
let lostLog = EventLog()
check("31 seed two copies of z1", legacyAppGroup.set("__secured_z_old", forKey: "z1", withAccessibility: .afterFirstUnlock) && legacy.set("__secured_z_new", forKey: "z1", withAccessibility: .afterFirstUnlock))
check("31 seed z2 and z3", legacy.set("__secured_z2", forKey: "z2", withAccessibility: .afterFirstUnlock) && legacy.set("__secured_z3", forKey: "z3", withAccessibility: .afterFirstUnlock))
lostVault.submitOperation(named: "set", key: "z1", run: { .locked }, lost: { lostVault.replaceLostValue("__secured_replaced", forKey: "z1") }, completion: { lostLog.record("set \(describe($0))") })
lostVault.queue.sync {}
lostTicker.fire(times: 2)
check("31 a stuck set waits through two retries", lostLog.events.isEmpty)
lostTicker.fire()
check("31 then the lost set replaces every copy with one fresh item", lostLog.events == ["set resolve true"] && groups("z1") == [appIdGroup] && lostVault.queue.sync { describe(lostVault.loadValue(forKey: "z1")) } == "resolve __secured_replaced", "\(lostLog.events) \(groups("z1"))")
lostVault.submitOperation(named: "get", key: "z2", run: { .locked }, lost: { lostVault.lostValue(forKey: "z2") }, completion: { lostLog.record("get \(describe($0)) \(code($0))") })
lostVault.submitOperation(named: "remove", key: "z2", run: { .locked }, lost: { lostVault.removeLostValue(forKey: "z2") }, completion: { lostLog.record("remove \(describe($0))") })
lostVault.queue.sync {}
lostTicker.fire(times: 3)
check("31 a lost get rejects as missing UNREADABLE", lostLog.events.contains("get reject Item with given key does not exist UNREADABLE"), "\(lostLog.events)")
lostTicker.fire(times: 3)
check("31 a lost remove deletes and resolves", lostLog.events.last == "remove resolve true" && items(account: "z2").isEmpty, "\(lostLog.events)")
lostVault.submitOperation(named: "clear", key: "*", run: { .locked }, lost: { lostVault.removeAllLostValues() }, completion: { lostLog.record("clear \(describe($0))") })
lostVault.queue.sync {}
lostTicker.fire(times: 3)
check("31 a lost clear deletes cap_sec and resolves", lostLog.events.last == "clear resolve true" && items().isEmpty)
check("31 lostItems counted", counter(diagnostics(lostVault), "lostItems") == 4 && counter(diagnostics(lostVault), "parked") == 4, "\(diagnostics(lostVault))")
check("31 the unlock probe leaves no items behind", items(in: service + ".probe").isEmpty)

print("--- 32 a parked get waits for the gate, then reads the migrated value")
cleanAll()
let gateFlag = Flag(false)
let gateTicker = HarnessTicker()
let gateVault = SecureStorageVault(bundleIdentifier: harnessBundle, isProtectedDataAvailable: { gateFlag.read() }, ticker: gateTicker)
let gateLog = EventLog()
check("32 seed legacy pin in the shared group", legacy.set("__secured_1234", forKey: "pin", withAccessibility: .afterFirstUnlock))
gateVault.submitOperation(named: "get", key: "pin", run: { gateVault.loadValue(forKey: "pin") }, lost: { gateVault.lostValue(forKey: "pin") }, completion: { gateLog.record("get \(describe($0))") })
gateVault.queue.sync {}
gateTicker.fire(times: 10)
check("32 parked while locked, nothing migrated", gateLog.events.isEmpty && groups("pin") == [sharedGroup] && accessible("pin") == ["ck"])
gateFlag.write(true)
gateTicker.fire()
check("32 resolves with the value after unlock, migrated", gateLog.events == ["get resolve __secured_1234"] && groups("pin") == [appIdGroup] && encrypted("pin") && accessible("pin") == ["aku"], "\(gateLog.events)")

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
    check("34 the plaintext fallback reads back", describe(zombieVault.loadValue(forKey: "zk2")) == "resolve __secured_z2")
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
    check("35 seed legacy plaintext in the shared group", legacy.set("__secured_c1", forKey: "c1", withAccessibility: .afterFirstUnlock))
    check("35 get of a legacy value whose new ciphertext does not decrypt returns the value", describe(checkVault.loadValue(forKey: "c1")) == "resolve __secured_c1")
    check("35 that migration fell back to plaintext with the strict class and the value still reads back", storedData("c1") == [Data("__secured_c1".utf8)] && accessible("c1") == ["aku"] && groups("c1") == [appIdGroup] && describe(checkVault.loadValue(forKey: "c1")) == "resolve __secured_c1", "\(accessible("c1")) \(groups("c1"))")

    // The check in memory passes, the read-back after the write does not: the write is undone.
    check("35 seed legacy plaintext in the app-ID group", legacyAppGroup.set("__secured_c2", forKey: "c2", withAccessibility: .afterFirstUnlock))
    checkVault.decryptCiphertext = decryptionFailing(after: 1)
    check("35 get returns the legacy value although the rewritten copy does not verify", describe(checkVault.loadValue(forKey: "c2")) == "resolve __secured_c2")
    check("35 an update that does not verify is put back: plaintext, ck, unmarked, app-ID group", storedData("c2") == [Data("__secured_c2".utf8)] && accessible("c2") == ["ck"] && marked("c2") == [false] && groups("c2") == [appIdGroup], "\(accessible("c2")) \(marked("c2"))")
    check("35 seed legacy plaintext in the shared group for an add", legacy.set("__secured_c3", forKey: "c3", withAccessibility: .afterFirstUnlock))
    checkVault.decryptCiphertext = decryptionFailing(after: 1)
    check("35 get returns the legacy value although the added copy does not verify", describe(checkVault.loadValue(forKey: "c3")) == "resolve __secured_c3")
    check("35 an add that does not verify is deleted again and the legacy copy stays as it was", groups("c3") == [sharedGroup] && storedData("c3") == [Data("__secured_c3".utf8)] && accessible("c3") == ["ck"], "\(groups("c3"))")
    checkVault.decryptCiphertext = SecKeyCreateDecryptedData
    check("35 once decryption works the sweep migrates them", describe(checkVault.migrateLegacyValues()) == "resolve -" && encrypted("c2") && encrypted("c3") && groups("c3") == [appIdGroup] && accessible("c2") == ["aku"] && accessible("c3") == ["aku"])
    check("35 the values read back", describe(checkVault.loadValue(forKey: "c2")) == "resolve __secured_c2" && describe(checkVault.loadValue(forKey: "c3")) == "resolve __secured_c3")
}

cleanAll()
check("cleanup items", items().isEmpty && allKeyCount() == 0)
print(failures == 0 ? "ALL PASS" : "FAILURES: \(failures)")
exit(failures == 0 ? 0 : 1)
