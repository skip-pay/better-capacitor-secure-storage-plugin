import Foundation
import Security

let service = "cap_sec"
let upstreamService = "cap_sec_upstream"
let upstreamStandardService = "harness.standard.upstream"
let appIdGroup = "ABCDE12345.capacitor-secure-storage-plugin.harness"
let keyTag = Data("capacitor-secure-storage-plugin.v1".utf8)
let simKeyTag = Data("capacitor-secure-storage-plugin.v1.sim".utf8)
let magic = Data([0x00, 0x53, 0x4B, 0x01])
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
    bundleIdentifier: String? = ProcessInfo.processInfo.environment["HARNESS_BUNDLE_ID"],
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
    for itemService in [service, upstreamService, upstreamStandardService, KeychainWrapper.standard.serviceName] { deleteService(itemService) }
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
    case .failure: return "failure"
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
    check("5 decodeValue invalid (not locked)", describe(vault.decodeValue(garbage)) == "invalid")
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
    check("17c r2 already aku, not rewritten", accessible("r2") == ["aku"] && modified("r2") == r2Seeded && !r2Seeded.isEmpty)
    check("17c encrypted ck r3 written by this version keeps its class and bytes", accessible("r3") == ["ck"] && storedData("r3") == r3Before)
    let r1Swept = modified("r1")
    check("17c new write gets the configured default class", describe(plainStrictVault.storeValue("__secured_r1b", forKey: "r1")) == "resolve true" && accessible("r1") == ["aku"] && storedData("r1") == [Data("__secured_r1b".utf8)])
    check("17c modification date detects the rewrite", modified("r1") != r1Swept)
}
let upstreamVault = makeVault(.afterFirstUnlock, encrypts: false, dedicatedService: upstreamService, standardService: upstreamStandardService)
upstreamVault.queue.sync {
    check("17d sweep with upstream defaults resolves", describe(upstreamVault.migrateLegacyValues()) == "resolve -")
    check("17d upstream item not rewritten", modified("u1", in: upstreamService) == u1Seeded && !u1Seeded.isEmpty && accessible("u1", in: upstreamService) == ["ck"])
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

cleanAll()
check("cleanup items", items().isEmpty && allKeyCount() == 0)
print(failures == 0 ? "ALL PASS" : "FAILURES: \(failures)")
exit(failures == 0 ? 0 : 1)
