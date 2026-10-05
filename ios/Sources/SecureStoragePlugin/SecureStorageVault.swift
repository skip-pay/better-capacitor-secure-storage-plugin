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

/// Protected-data and app-state signals. The plugin writes them from UIKit notifications on the main thread and the vault
/// reads them on its own queue, so neither side waits for the other. `nil` protected data means not known yet.
final class SecureStorageSignals {
    private let lock = NSLock()
    private var protectedData: Bool?
    private var active: Bool

    init(protectedDataAvailable: Bool? = nil, applicationActive: Bool = false) {
        protectedData = protectedDataAvailable
        active = applicationActive
    }

    var isProtectedDataAvailable: Bool? {
        lock.lock()
        defer { lock.unlock() }
        return protectedData
    }

    var isApplicationActive: Bool {
        lock.lock()
        defer { lock.unlock() }
        return active
    }

    func setProtectedDataAvailable(_ available: Bool) {
        lock.lock()
        protectedData = available
        lock.unlock()
    }

    func setApplicationActive(_ isActive: Bool) {
        lock.lock()
        active = isActive
        lock.unlock()
    }
}

/// Repeating timer that re-runs the parked queue. The vault starts and stops it on its own queue only.
protocol SecureStorageTicker: AnyObject {
    func start(on queue: DispatchQueue, handler: @escaping () -> Void)
    func stop()
}

final class SecureStorageDispatchTicker: SecureStorageTicker {
    private let interval: DispatchTimeInterval
    private var timer: DispatchSourceTimer?

    init(interval: DispatchTimeInterval = .seconds(1)) {
        self.interval = interval
    }

    deinit {
        timer?.cancel()
    }

    func start(on queue: DispatchQueue, handler: @escaping () -> Void) {
        guard timer == nil else { return }
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + interval, repeating: interval, leeway: .milliseconds(100))
        source.setEventHandler(handler: handler)
        source.resume()
        timer = source
    }

    func stop() {
        timer?.cancel()
        timer = nil
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

        init(accessibility: Accessibility = .whenUnlockedThisDeviceOnly, encryptsValues: Bool = true) {
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
        case reject(String, code: String? = nil)
        case locked
    }

    struct Counters {
        var parked = 0
        var lostItems = 0
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

    private final class PendingOperation {
        let name: String
        let key: String
        let run: () -> Outcome
        let lost: (() -> Outcome)?
        let complete: ((Outcome) -> Void)?
        var wasParked = false
        var confirmedLockedAttempts = 0
        var lastCountedTick: Int?

        init(name: String, key: String, run: @escaping () -> Outcome, lost: (() -> Outcome)?, complete: ((Outcome) -> Void)?) {
            self.name = name
            self.key = key
            self.run = run
            self.lost = lost
            self.complete = complete
        }
    }

    private typealias KeyCandidate = (tag: Data, secureEnclave: Bool)

    static let magic = Data([0x00, 0x53, 0x4B, 0x01])
    static let missingItemMessage = "Item with given key does not exist"
    static let undecryptableItemMessage = "Item with given key could not be decrypted"
    static let unsupportedAccessibilityMessage = "Unsupported accessibility value"
    static let unsupportedConfigurationMessage = "Unsupported accessibility value in plugin configuration"
    static let unreadableCode = "UNREADABLE"
    /// Retries after the first locked result seen while protected data is available, at most one per timer tick.
    static let lockedRetriesBeforeLost = 3

    let queue = DispatchQueue(label: "capacitor-secure-storage-plugin.vault")
    let configuration: Configuration
    let dedicated: SecureStorageItemStore
    let standard: SecureStorageItemStore

    private static let keyLock = NSLock()
    private static var cachedKeys: [Data: SecKey] = [:]

    private let keyTag: Data
    private let keyCandidates: [KeyCandidate]
    private let isProtectedDataAvailable: () -> Bool?
    private let refreshSignals: () -> Void
    private let unlockProbe: (() -> Bool)?
    private let ticker: SecureStorageTicker
    private let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private let logger = Logger(subsystem: "capacitor-secure-storage-plugin", category: "vault")
    private var parkedOperations: [PendingOperation] = []
    private var tickerRunning = false
    private var tickCount = 0
    /// Only read or written on `queue`.
    private(set) var counters = Counters()

    /// - Parameters:
    ///   - isProtectedDataAvailable: cheap pre-check, `nil` while not known yet. Unknown counts as available and the keychain's
    ///     own `errSecInteractionNotAllowed` decides.
    ///   - refreshSignals: asks the owner to re-read the protected-data state. Called on timer ticks while calls are parked and
    ///     the state is not known to be available, so a missed notification cannot strand the queue.
    ///   - unlockProbe: confirms that the keychain accepts an unlock-bound write before a stuck item is classified as lost.
    ///     `nil` uses a throwaway keychain item.
    ///   - ticker: re-runs the parked queue while it is not empty.
    init(
        configuration: Configuration = Configuration(),
        dedicatedService: String = "cap_sec",
        standardService: String = Bundle.main.bundleIdentifier ?? "SwiftKeychainWrapper",
        keyTag: String = "capacitor-secure-storage-plugin.v1",
        isProtectedDataAvailable: @escaping () -> Bool? = { true },
        refreshSignals: @escaping () -> Void = {},
        unlockProbe: (() -> Bool)? = nil,
        ticker: SecureStorageTicker = SecureStorageDispatchTicker()
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
        self.refreshSignals = refreshSignals
        self.unlockProbe = unlockProbe
        self.ticker = ticker
    }

    deinit {
        ticker.stop()
    }

    /// Queues an operation behind every parked one. A `.locked` outcome parks it until a later drain or timer tick.
    /// `lost` replaces `run` once the operation keeps reporting a locked keychain while protected data is available
    /// (`lockedRetriesBeforeLost`). Without `lost` such an operation rejects as missing with code `UNREADABLE`.
    func submitOperation(named name: String, key: String, run: @escaping () -> Outcome, lost: (() -> Outcome)? = nil, completion: ((Outcome) -> Void)? = nil) {
        let operation = PendingOperation(name: name, key: key, run: run, lost: lost, complete: completion)
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

    /// One timer tick. Runs on `queue`.
    func tick() {
        tickCount += 1
        if isProtectedDataAvailable() != true {
            refreshSignals()
        }
        runParkedOperations()
    }

    /// Only meaningful on `queue`.
    var isTickerRunning: Bool {
        return tickerRunning
    }

    /// Only meaningful on `queue`.
    var parkedCount: Int {
        return parkedOperations.count
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

    /// `set` for an item the keychain keeps refusing while unlocked: drop every copy, then write a fresh one.
    func replaceLostValue(_ value: String, forKey key: String, accessibility: Accessibility? = nil) -> Outcome {
        _ = classifyStatus(dedicated.deleteItem(key), context: "delete lost \(key)")
        _ = classifyStatus(standard.deleteItem(key), context: "delete lost standard \(key)")
        return storeValue(value, forKey: key, accessibility: accessibility)
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

    /// `get` for an item the keychain keeps refusing while unlocked.
    func lostValue(forKey key: String) -> Outcome {
        return .reject(SecureStorageVault.missingItemMessage, code: SecureStorageVault.unreadableCode)
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

    /// `keys` while the keychain keeps refusing the listing although the device is unlocked.
    func lostKeyList() -> Outcome {
        return .resolve(["value": [String]()])
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

    /// `remove` for an item the keychain keeps refusing while unlocked. The app cannot read it any more, so it counts as removed.
    func removeLostValue(forKey key: String) -> Outcome {
        _ = classifyStatus(dedicated.deleteItem(key), context: "delete lost \(key)")
        _ = classifyStatus(standard.deleteItem(key), context: "delete lost standard \(key)")
        return .resolve(["value": true])
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

    /// `clear` while the keychain keeps refusing it although the device is unlocked.
    func removeAllLostValues() -> Outcome {
        _ = classifyStatus(dedicated.deleteAll(), context: "clear lost")
        return .resolve(["value": true])
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

    /// Writes and deletes a throwaway item with an unlock-bound class. Only an explicit `errSecInteractionNotAllowed` counts as
    /// locked, any other result leaves the decision to the protected-data signal.
    func confirmUnlocked() -> Bool {
        if let probe = unlockProbe {
            return probe()
        }
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: dedicated.service + ".probe",
            kSecAttrAccount as String: Data("unlock.\(UUID().uuidString)".utf8),
            kSecAttrSynchronizable as String: false,
        ]
        let add = probe.merging([
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: Data(),
        ]) { _, new in new }
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecSuccess {
            SecItemDelete(probe as CFDictionary)
        }
        if status == errSecInteractionNotAllowed {
            logger.notice("unlock probe locked")
            return false
        }
        return true
    }

    private func resolveMigrationAccessibility(_ existing: String?) -> Accessibility {
        guard let current = existing.flatMap(Accessibility.init(attribute:)) else { return configuration.accessibility }
        return current.tightened(toAtLeast: configuration.accessibility)
    }

    private func runParkedOperations() {
        let operations = parkedOperations
        var remaining: [PendingOperation] = []
        for (index, operation) in operations.enumerated() {
            guard executeOperation(operation) else {
                remaining = Array(operations[index...])
                break
            }
        }
        parkedOperations = remaining
        updateTicker()
    }

    private func updateTicker() {
        if parkedOperations.isEmpty {
            guard tickerRunning else { return }
            ticker.stop()
            tickerRunning = false
        } else {
            guard !tickerRunning else { return }
            tickerRunning = true
            ticker.start(on: queue) { [weak self] in self?.tick() }
        }
    }

    private func executeOperation(_ operation: PendingOperation) -> Bool {
        let gated = configuration.accessibility.requiresUnlock && isProtectedDataAvailable() == false
        var outcome = gated ? .locked : operation.run()
        if !gated, case .locked = outcome, isProtectedDataAvailable() == true, countLockedWhileUnlocked(operation) {
            counters.lostItems += 1
            logger.fault("lost \(operation.name, privacy: .public) \(operation.key, privacy: .public) after \(operation.confirmedLockedAttempts, privacy: .public) locked results while unlocked")
            outcome = operation.lost?() ?? .reject(SecureStorageVault.missingItemMessage, code: SecureStorageVault.unreadableCode)
            if case .locked = outcome {
                outcome = .reject("error")
            }
        }
        switch outcome {
        case .locked:
            if !operation.wasParked {
                operation.wasParked = true
                counters.parked += 1
            }
            logger.notice("parked \(operation.name, privacy: .public) \(operation.key, privacy: .public)")
            return false
        case .reject(let message, _) where message != SecureStorageVault.missingItemMessage:
            logger.notice("rejected \(operation.name, privacy: .public) \(operation.key, privacy: .public): \(message, privacy: .public)")
        case .reject, .resolve:
            break
        }
        operation.complete?(outcome)
        return true
    }

    /// Counts a locked result seen while protected data is known to be available, at most once per timer tick and only when
    /// the unlock probe agrees, so a stale signal never turns a locked device into lost items. True once the retries are used up.
    private func countLockedWhileUnlocked(_ operation: PendingOperation) -> Bool {
        if let last = operation.lastCountedTick, last == tickCount {
            return false
        }
        guard confirmUnlocked() else { return false }
        operation.lastCountedTick = tickCount
        operation.confirmedLockedAttempts += 1
        return operation.confirmedLockedAttempts > SecureStorageVault.lockedRetriesBeforeLost
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
        if code == Int(errSecInteractionNotAllowed) || isProtectedDataAvailable() == false {
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
