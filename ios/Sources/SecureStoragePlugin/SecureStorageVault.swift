import Foundation
import Security
import os

struct SecureStorageItemStore {
    let service: String

    func readItem(_ key: String) -> (status: OSStatus, data: Data, accessibility: String?) {
        var query = makeItemQuery(key)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return (status, Data(), nil) }
        guard let attributes = result as? [String: Any], let data = attributes[kSecValueData as String] as? Data else {
            return (errSecDecode, Data(), nil)
        }
        return (status, data, attributes[kSecAttrAccessible as String] as? String)
    }

    func writeItem(_ key: String, data: Data, accessibility: CFString) -> OSStatus {
        let query = makeItemQuery(key)
        let attributes: [String: Any] = [
            kSecAttrAccessible as String: accessibility,
            kSecValueData as String: data,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard updateStatus == errSecItemNotFound else { return updateStatus }
        let addQuery = query.merging(attributes) { _, new in new }
        return SecItemAdd(addQuery as CFDictionary, nil)
    }

    func deleteItem(_ key: String) -> OSStatus {
        return SecItemDelete(makeItemQuery(key) as CFDictionary)
    }

    func listKeys() -> (status: OSStatus, keys: [String]) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return (errSecSuccess, []) }
        guard status == errSecSuccess else { return (status, []) }
        var keys: [String] = []
        for attributes in result as? [[String: Any]] ?? [] {
            guard let key = decodeAccount(attributes[kSecAttrAccount as String]), !keys.contains(key) else { continue }
            keys.append(key)
        }
        return (status, keys)
    }

    func deleteAll() -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        return SecItemDelete(query as CFDictionary)
    }

    private func decodeAccount(_ account: Any?) -> String? {
        if let data = account as? Data {
            return String(data: data, encoding: .utf8)
        }
        return account as? String
    }

    private func makeItemQuery(_ key: String) -> [String: Any] {
        // SwiftKeychainWrapper item shape: account and generic as Data, no access group because legacy items live in two groups.
        let account = Data(key.utf8)
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrGeneric as String: account,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
    }
}

final class SecureStorageVault {
    enum Accessibility: String, CaseIterable {
        case whenUnlocked
        case whenUnlockedThisDeviceOnly
        case afterFirstUnlock
        case afterFirstUnlockThisDeviceOnly
        case whenPasscodeSetThisDeviceOnly

        var attribute: CFString {
            switch self {
            case .whenUnlocked:
                return kSecAttrAccessibleWhenUnlocked
            case .whenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlock:
                return kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .whenPasscodeSetThisDeviceOnly:
                return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }
        }

        var requiresUnlock: Bool {
            return unlockLevel > 0
        }

        private var unlockLevel: Int {
            switch self {
            case .afterFirstUnlock, .afterFirstUnlockThisDeviceOnly:
                return 0
            case .whenUnlocked, .whenUnlockedThisDeviceOnly:
                return 1
            case .whenPasscodeSetThisDeviceOnly:
                return 2
            }
        }

        private var isDeviceBound: Bool {
            switch self {
            case .afterFirstUnlock, .whenUnlocked:
                return false
            case .afterFirstUnlockThisDeviceOnly, .whenUnlockedThisDeviceOnly, .whenPasscodeSetThisDeviceOnly:
                return true
            }
        }

        init?(attribute: String) {
            guard let match = Accessibility.allCases.first(where: { $0.attribute as String == attribute }) else { return nil }
            self = match
        }

        func tightened(toAtLeast other: Accessibility) -> Accessibility {
            switch (max(unlockLevel, other.unlockLevel), isDeviceBound || other.isDeviceBound) {
            case (2, _):
                return .whenPasscodeSetThisDeviceOnly
            case (1, true):
                return .whenUnlockedThisDeviceOnly
            case (1, false):
                return .whenUnlocked
            case (_, true):
                return .afterFirstUnlockThisDeviceOnly
            case (_, false):
                return .afterFirstUnlock
            }
        }
    }

    struct Configuration {
        let accessibility: Accessibility
        let encryptsValues: Bool

        init(accessibility: Accessibility = .afterFirstUnlock, encryptsValues: Bool = false) {
            self.accessibility = accessibility
            self.encryptsValues = encryptsValues
        }

        init?(requestedAccessibility: String?, encryptsValues: Bool) {
            guard let requested = requestedAccessibility else {
                self.init(encryptsValues: encryptsValues)
                return
            }
            guard let accessibility = Accessibility(rawValue: requested) else { return nil }
            self.init(accessibility: accessibility, encryptsValues: encryptsValues)
        }
    }

    enum EncodeResult {
        case encoded(Data)
        case locked
        case failure
    }

    enum DecodeResult {
        case plaintext(String)
        case decrypted(String)
        case locked
        case invalid
        case failure
    }

    enum Outcome {
        case resolve([String: Any])
        case reject(String)
        case locked
    }

    private enum KeyResult {
        case key(SecKey)
        case locked
        case failure
    }

    private enum StatusClass {
        case ok
        case notFound
        case locked
        case failed
    }

    private struct PendingOperation {
        let name: String
        let key: String
        let run: () -> Outcome
        let complete: ((Outcome) -> Void)?
    }

    private typealias KeyCandidate = (tag: Data, secureEnclave: Bool)

    static let magic = Data([0x00, 0x53, 0x4B, 0x01])
    static let missingItemMessage = "Item with given key does not exist"
    static let undecryptableItemMessage = "Item with given key could not be decrypted"
    static let unsupportedAccessibilityMessage = "Unsupported accessibility value"
    static let unsupportedConfigurationMessage = "Unsupported accessibility value in plugin configuration"

    let queue = DispatchQueue(label: "capacitor-secure-storage-plugin.vault")
    let configuration: Configuration
    let dedicated: SecureStorageItemStore
    let standard: SecureStorageItemStore

    private static let keyLock = NSLock()
    private static var cachedKeys: [Data: SecKey] = [:]

    private let keyTag: Data
    private let keyCandidates: [KeyCandidate]
    private let isProtectedDataAvailable: () -> Bool
    private let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private let logger = Logger(subsystem: "capacitor-secure-storage-plugin", category: "vault")
    private var parkedOperations: [PendingOperation] = []

    init(
        configuration: Configuration = Configuration(),
        dedicatedService: String = "cap_sec",
        standardService: String = Bundle.main.bundleIdentifier ?? "SwiftKeychainWrapper",
        keyTag: String = "capacitor-secure-storage-plugin.v1",
        isProtectedDataAvailable: @escaping () -> Bool = { true }
    ) {
        self.configuration = configuration
        dedicated = SecureStorageItemStore(service: dedicatedService)
        standard = SecureStorageItemStore(service: standardService)
        self.keyTag = Data(keyTag.utf8)
        #if targetEnvironment(simulator)
        keyCandidates = [(tag: Data(keyTag.utf8), secureEnclave: true), (tag: Data((keyTag + ".sim").utf8), secureEnclave: false)]
        #else
        keyCandidates = [(tag: Data(keyTag.utf8), secureEnclave: true)]
        #endif
        self.isProtectedDataAvailable = isProtectedDataAvailable
    }

    func submitOperation(named name: String, key: String, run: @escaping () -> Outcome, completion: ((Outcome) -> Void)? = nil) {
        let operation = PendingOperation(name: name, key: key, run: run, complete: completion)
        queue.async {
            self.parkedOperations.append(operation)
            self.runParkedOperations()
        }
    }

    func drainParkedOperations() {
        queue.async {
            self.runParkedOperations()
        }
    }

    func resolveAccessibility(_ requested: String?) -> Accessibility? {
        guard let requested = requested else { return configuration.accessibility }
        return Accessibility(rawValue: requested)
    }

    func storeValue(_ value: String, forKey key: String, accessibility: Accessibility? = nil) -> Outcome {
        let data: Data
        switch encodeValue(value) {
        case .encoded(let encoded):
            data = encoded
        case .locked:
            return .locked
        case .failure:
            return .reject("error")
        }
        let attribute = (accessibility ?? configuration.accessibility).attribute
        switch classifyStatus(dedicated.writeItem(key, data: data, accessibility: attribute), context: "write \(key)") {
        case .ok:
            return .resolve(["value": true])
        case .locked:
            return .locked
        case .notFound, .failed:
            return .reject("error")
        }
    }

    func loadValue(forKey key: String) -> Outcome {
        let read = dedicated.readItem(key)
        switch classifyStatus(read.status, context: "read \(key)") {
        case .ok:
            return resolveStoredValue(read.data, forKey: key)
        case .notFound:
            return migrateStandardValue(forKey: key)
        case .locked:
            return .locked
        case .failed:
            return .reject("error")
        }
    }

    func listStoredKeys() -> Outcome {
        let list = dedicated.listKeys()
        switch classifyStatus(list.status, context: "list") {
        case .ok, .notFound:
            return .resolve(["value": list.keys])
        case .locked:
            return .locked
        case .failed:
            return .reject("error")
        }
    }

    func removeValue(forKey key: String) -> Outcome {
        var existed = false
        for store in [dedicated, standard] {
            switch classifyStatus(store.readItem(key).status, context: "read \(key) in \(store.service) before remove") {
            case .ok, .failed:
                existed = true
            case .notFound:
                break
            case .locked:
                return .locked
            }
        }
        guard existed else { return .reject(SecureStorageVault.missingItemMessage) }
        var removed = true
        for store in [dedicated, standard] {
            switch classifyStatus(store.deleteItem(key), context: "delete \(key) in \(store.service)") {
            case .ok, .notFound:
                break
            case .locked:
                return .locked
            case .failed:
                removed = false
            }
        }
        return removed ? .resolve(["value": true]) : .reject("Remove failed")
    }

    func removeAllValues() -> Outcome {
        let list = dedicated.listKeys()
        if case .locked = classifyStatus(list.status, context: "list before clear") {
            return .locked
        }
        var cleared = true
        let deletions: [() -> OSStatus] = list.keys.map { key in { self.standard.deleteItem(key) } } + [{ self.dedicated.deleteAll() }]
        for delete in deletions {
            switch classifyStatus(delete(), context: "clear") {
            case .ok, .notFound:
                break
            case .locked:
                return .locked
            case .failed:
                cleared = false
            }
        }
        return cleared ? .resolve(["value": true]) : .reject("error")
    }

    func migrateLegacyValues() -> Outcome {
        guard configuration.encryptsValues else { return .resolve([:]) }
        let list = dedicated.listKeys()
        switch classifyStatus(list.status, context: "list for sweep") {
        case .ok, .notFound:
            return migrateKeys(list.keys, using: migrateLegacyValue(forKey:))
        case .locked:
            logger.notice("sweep skipped while locked")
            return .resolve([:])
        case .failed:
            return .reject("error")
        }
    }

    func migrateKeys(_ keys: [String], using migrate: (String) -> Outcome) -> Outcome {
        for key in keys {
            if case .locked = migrate(key) {
                logger.notice("sweep skipped \(key, privacy: .public) while locked")
            }
        }
        return .resolve([:])
    }

    func migrateLegacyValue(forKey key: String) -> Outcome {
        let read = dedicated.readItem(key)
        switch classifyStatus(read.status, context: "read \(key) for migration") {
        case .ok:
            break
        case .notFound:
            return .resolve([:])
        case .locked:
            return .locked
        case .failed:
            return .reject("error")
        }
        guard !isEncodedValue(read.data) else { return .resolve([:]) }
        guard let value = String(data: read.data, encoding: .utf8) else { return .reject("error") }
        let outcome = storeValue(value, forKey: key, accessibility: resolveMigrationAccessibility(read.accessibility))
        if case .resolve = outcome {
            logger.notice("migrated \(key, privacy: .public)")
        }
        return outcome
    }

    func migrateStandardValue(forKey key: String) -> Outcome {
        let read = standard.readItem(key)
        switch classifyStatus(read.status, context: "read standard \(key)") {
        case .ok:
            break
        case .notFound:
            return .reject(SecureStorageVault.missingItemMessage)
        case .locked:
            return .locked
        case .failed:
            return .reject("error")
        }
        guard let value = String(data: read.data, encoding: .utf8) else {
            return .reject(SecureStorageVault.undecryptableItemMessage)
        }
        let outcome = storeValue(value, forKey: key, accessibility: resolveMigrationAccessibility(read.accessibility))
        guard case .resolve = outcome else { return outcome }
        _ = classifyStatus(standard.deleteItem(key), context: "delete standard \(key) after migration")
        logger.notice("migrated standard \(key, privacy: .public)")
        return .resolve(["value": value])
    }

    func isEncodedValue(_ data: Data) -> Bool {
        return data.starts(with: SecureStorageVault.magic)
    }

    func encodeValue(_ value: String) -> EncodeResult {
        let plaintext = Data(value.utf8)
        guard configuration.encryptsValues else { return .encoded(plaintext) }
        let key: SecKey
        switch acquirePrivateKey() {
        case .key(let acquired):
            key = acquired
        case .locked:
            return .locked
        case .failure:
            return .failure
        }
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            logger.error("public key unavailable")
            return .failure
        }
        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(publicKey, algorithm, plaintext as CFData, &error) as Data? else {
            return isLockedFailure(error, context: "encrypt") ? .locked : .failure
        }
        return .encoded(SecureStorageVault.magic + ciphertext)
    }

    func decodeValue(_ data: Data) -> DecodeResult {
        guard isEncodedValue(data) else {
            guard let value = String(data: data, encoding: .utf8) else { return .invalid }
            return .plaintext(value)
        }
        let key: SecKey
        switch acquirePrivateKey() {
        case .key(let acquired):
            key = acquired
        case .locked:
            return .locked
        case .failure:
            return .failure
        }
        let ciphertext = Data(data.dropFirst(SecureStorageVault.magic.count))
        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(key, algorithm, ciphertext as CFData, &error) as Data? else {
            return isLockedFailure(error, context: "decrypt") ? .locked : .invalid
        }
        guard let value = String(data: plaintext, encoding: .utf8) else { return .invalid }
        return .decrypted(value)
    }

    private func resolveMigrationAccessibility(_ existing: String?) -> Accessibility {
        guard let current = existing.flatMap(Accessibility.init(attribute:)) else { return configuration.accessibility }
        return current.tightened(toAtLeast: configuration.accessibility)
    }

    private func runParkedOperations() {
        let operations = parkedOperations
        for (index, operation) in operations.enumerated() {
            guard executeOperation(operation) else {
                parkedOperations = Array(operations[index...])
                return
            }
        }
        parkedOperations = []
    }

    private func executeOperation(_ operation: PendingOperation) -> Bool {
        let gated = configuration.accessibility.requiresUnlock && !isProtectedDataAvailable()
        let outcome = gated ? .locked : operation.run()
        switch outcome {
        case .locked:
            logger.notice("parked \(operation.name, privacy: .public) \(operation.key, privacy: .public)")
            return false
        case .reject(let message) where message != SecureStorageVault.missingItemMessage:
            logger.notice("rejected \(operation.name, privacy: .public) \(operation.key, privacy: .public): \(message, privacy: .public)")
        case .reject, .resolve:
            break
        }
        operation.complete?(outcome)
        return true
    }

    private func resolveStoredValue(_ data: Data, forKey key: String) -> Outcome {
        switch decodeValue(data) {
        case .decrypted(let value):
            return .resolve(["value": value])
        case .plaintext(let value):
            if configuration.encryptsValues {
                submitOperation(named: "migrate", key: key, run: { self.migrateLegacyValue(forKey: key) })
            }
            return .resolve(["value": value])
        case .locked:
            return .locked
        case .invalid:
            return .reject(SecureStorageVault.undecryptableItemMessage)
        case .failure:
            return .reject("error")
        }
    }

    private func acquirePrivateKey() -> KeyResult {
        SecureStorageVault.keyLock.lock()
        defer { SecureStorageVault.keyLock.unlock() }
        if let key = SecureStorageVault.cachedKeys[keyTag] {
            return .key(key)
        }
        for candidate in keyCandidates {
            var query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: candidate.tag,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true,
            ]
            if candidate.secureEnclave {
                query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            }
            var result: CFTypeRef?
            switch classifyStatus(SecItemCopyMatching(query as CFDictionary, &result), context: "key lookup") {
            case .ok:
                guard let reference = result, CFGetTypeID(reference) == SecKeyGetTypeID() else {
                    logger.error("key lookup returned no key reference")
                    return .failure
                }
                let key = reference as! SecKey
                SecureStorageVault.cachedKeys[keyTag] = key
                return .key(key)
            case .notFound:
                continue
            case .locked:
                return .locked
            case .failed:
                return .failure
            }
        }
        for candidate in keyCandidates {
            switch generatePrivateKey(candidate) {
            case .key(let key):
                SecureStorageVault.cachedKeys[keyTag] = key
                return .key(key)
            case .locked:
                return .locked
            case .failure:
                continue
            }
        }
        return .failure
    }

    private func generatePrivateKey(_ candidate: KeyCandidate) -> KeyResult {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error) else {
            logger.fault("access control creation failed \(self.extractCode(from: error), privacy: .public)")
            return .failure
        }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: candidate.tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        if candidate.secureEnclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return isLockedFailure(error, context: "key creation secureEnclave \(candidate.secureEnclave)") ? .locked : .failure
        }
        logger.notice("created key secureEnclave \(candidate.secureEnclave, privacy: .public)")
        return .key(key)
    }

    private func classifyStatus(_ status: OSStatus, context: String) -> StatusClass {
        switch status {
        case errSecSuccess:
            return .ok
        case errSecItemNotFound:
            return .notFound
        case errSecInteractionNotAllowed:
            return .locked
        default:
            logger.error("\(context, privacy: .public) failed \(status, privacy: .public)")
            return .failed
        }
    }

    private func isLockedFailure(_ error: Unmanaged<CFError>?, context: String) -> Bool {
        let code = extractCode(from: error)
        if code == Int(errSecInteractionNotAllowed) || !isProtectedDataAvailable() {
            logger.notice("\(context, privacy: .public) locked \(code, privacy: .public)")
            return true
        }
        logger.error("\(context, privacy: .public) failed \(code, privacy: .public)")
        return false
    }

    private func extractCode(from error: Unmanaged<CFError>?) -> Int {
        guard let error = error?.takeRetainedValue() else { return Int(errSecInternalError) }
        return CFErrorGetCode(error)
    }
}
