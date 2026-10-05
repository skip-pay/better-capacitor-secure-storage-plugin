import Foundation
import Security
import os

struct SecureStorageItemStore {
    /// One keychain item for a key. A key can have several, one per access group.
    struct Copy {
        let accessGroup: String?
        let accessibility: String?
        let modified: Date?
        let persistentRef: Data?
        let label: String?
        /// Written by this plugin version, so its class was chosen by a `set` and a migration keeps it.
        var isMarked: Bool {
            return label == SecureStorageItemStore.marker
        }
    }

    /// Label on every item this version writes. Not part of any query, so the 0.13.0 query shape still finds the items.
    static let marker = "better-capacitor-secure-storage-plugin"

    let service: String

    /// Reads one item. Without a group the keychain searches every group the app can access and returns any match.
    func readItem(_ key: String, accessGroup: String? = nil) -> (status: OSStatus, data: Data, accessibility: String?) {
        var query = makeItemQuery(key, accessGroup: accessGroup)
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

    /// Every copy of a key across all accessible groups, attributes and persistent references only.
    func copies(of key: String) -> (status: OSStatus, copies: [Copy]) {
        var query = makeItemQuery(key)
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = true
        query[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return (errSecSuccess, []) }
        guard status == errSecSuccess else { return (status, []) }
        let copies = (result as? [[String: Any]] ?? []).map { attributes in
            Copy(
                accessGroup: attributes[kSecAttrAccessGroup as String] as? String,
                accessibility: attributes[kSecAttrAccessible as String] as? String,
                modified: attributes[kSecAttrModificationDate as String] as? Date,
                persistentRef: attributes[kSecValuePersistentRef as String] as? Data,
                label: attributes[kSecAttrLabel as String] as? String
            )
        }
        return (status, copies)
    }

    /// The copy upstream 0.13.0 read: SwiftKeychainWrapper's query without an access group, limit one, as a persistent reference.
    func upstreamCopyReference(of key: String) -> (status: OSStatus, reference: Data?) {
        var query = makeItemQuery(key)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result as? Data)
    }

    /// Reads the data of one copy, by its group.
    func readCopy(_ copy: Copy, of key: String) -> (status: OSStatus, data: Data) {
        guard let group = copy.accessGroup else { return (errSecParam, Data()) }
        let read = readItem(key, accessGroup: group)
        return (read.status, read.data)
    }

    /// Rewrites one copy in its group with new data and class and leaves its label alone, so an unmarked copy stays
    /// unmarked and keeps ranking below the copies this version wrote.
    func rewriteCopy(_ copy: Copy, of key: String, data: Data, accessibility: CFString) -> OSStatus {
        guard let group = copy.accessGroup else { return errSecParam }
        let attributes: [String: Any] = [
            kSecAttrAccessible as String: accessibility,
            kSecValueData as String: data,
        ]
        return SecItemUpdate(makeItemQuery(key, accessGroup: group) as CFDictionary, attributes as CFDictionary)
    }

    /// Puts back what the copy in `accessGroup` held before a write that did not verify: data, class and label.
    func restoreItem(_ key: String, data: Data, accessibility: String?, label: String?, accessGroup: String) -> OSStatus {
        var attributes: [String: Any] = [
            kSecValueData as String: data,
            // There is no way to drop an attribute. An empty label is not the marker either.
            kSecAttrLabel as String: label ?? "",
        ]
        if let accessibility = accessibility {
            attributes[kSecAttrAccessible as String] = accessibility
        }
        return SecItemUpdate(makeItemQuery(key, accessGroup: accessGroup) as CFDictionary, attributes as CFDictionary)
    }

    /// Updates the item in `accessGroup` (every copy when `nil`) and adds it there when it does not exist yet.
    func writeItem(_ key: String, data: Data, accessibility: CFString, accessGroup: String? = nil) -> OSStatus {
        let updateStatus = updateItem(key, data: data, accessibility: accessibility, accessGroup: accessGroup)
        guard updateStatus == errSecItemNotFound else { return updateStatus }
        return addItem(key, data: data, accessibility: accessibility, accessGroup: accessGroup)
    }

    func addItem(_ key: String, data: Data, accessibility: CFString, accessGroup: String?) -> OSStatus {
        var query = makeItemQuery(key, accessGroup: accessGroup)
        query[kSecAttrAccessible as String] = accessibility
        query[kSecValueData as String] = data
        query[kSecAttrLabel as String] = SecureStorageItemStore.marker
        return SecItemAdd(query as CFDictionary, nil)
    }

    func updateItem(_ key: String, data: Data, accessibility: CFString, accessGroup: String?) -> OSStatus {
        let attributes: [String: Any] = [
            kSecAttrAccessible as String: accessibility,
            kSecValueData as String: data,
            kSecAttrLabel as String: SecureStorageItemStore.marker,
        ]
        return SecItemUpdate(makeItemQuery(key, accessGroup: accessGroup) as CFDictionary, attributes as CFDictionary)
    }

    /// Deletes the key in every accessible group.
    func deleteItem(_ key: String) -> OSStatus {
        return SecItemDelete(makeItemQuery(key) as CFDictionary)
    }

    func deleteCopy(_ copy: Copy, of key: String) -> OSStatus {
        guard let reference = copy.persistentRef else {
            guard let group = copy.accessGroup else { return errSecParam }
            return SecItemDelete(makeItemQuery(key, accessGroup: group) as CFDictionary)
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecValuePersistentRef as String: reference,
        ]
        return SecItemDelete(query as CFDictionary)
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

    /// Deletes every item of the service in every accessible group. Items of other services and items without a service stay.
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

    private func makeItemQuery(_ key: String, accessGroup: String? = nil) -> [String: Any] {
        // SwiftKeychainWrapper item shape (account and generic as Data, not synchronizable), so the 0.13.0 query still finds items.
        let account = Data(key.utf8)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrGeneric as String: account,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
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

    /// Where writes go. `explicitGroup` is the app-private `<TEAM>.<bundle id>` group, `nil` after a fallback.
    /// `defaultGroup` is the group the keychain picks without an explicit one, as reported for a throwaway item.
    struct AccessGroupMode: Equatable {
        let explicitGroup: String?
        let defaultGroup: String?

        var targetGroup: String? {
            return explicitGroup ?? defaultGroup
        }

        var isExplicit: Bool {
            return explicitGroup != nil
        }
    }

    enum EncodeResult {
        case encoded(Data)
        case locked
        case failure
    }

    /// `.invalid` is final: the bytes cannot be decoded with any key this app has. `.locked` parks the call, also for a
    /// failure that is not known to be permanent, so the tick-bounded key count (`noteKeyRefusal`) or the lost escape decides
    /// instead of the first attempt.
    enum DecodeResult {
        case plaintext(String)
        case decrypted(String)
        case locked
        case invalid
    }

    /// Rejection codes, additive to the unchanged messages.
    enum ErrorCode: String {
        case notFound = "NOT_FOUND"
        case unreadable = "UNREADABLE"
        /// Reserved for a future fail-fast option. The default path parks locked calls and never emits it.
        case locked = "LOCKED"
        case unsupportedAccessibility = "UNSUPPORTED_ACCESSIBILITY"
        case storageError = "STORAGE_ERROR"
    }

    enum Outcome {
        case resolve([String: Any])
        case reject(String, code: ErrorCode)
        case locked
    }

    /// Result of reading one key across all of its copies.
    enum SettleResult {
        case value(String)
        case missing
        case locked
        case unreadable
        case failure
    }

    struct Counters {
        var parked = 0
        var migrated = 0
        var duplicatesResolved = 0
        var lostItems = 0
        var decryptFailures = 0
        var plaintextFallbacks = 0
        var decryptRetries = 0
        var conflictingDuplicates = 0
    }

    private enum KeyResult {
        case key(SecKey)
        case missing
        case locked
        case failure
        /// The key keeps refusing with -25308, or failing for a reason not known to be permanent, on a device confirmed to be
        /// unlocked, see `noteKeyRefusal`.
        case unusable
    }

    private enum StatusClass {
        case ok
        case notFound
        case locked
        case failed
    }

    private enum DecryptResult {
        case plaintext(Data)
        /// The device is locked or not confirmed to be unlocked.
        case locked
        /// Still failing after the retries on a device confirmed to be unlocked, or the key lookup failed.
        case failed(DecryptFailure)
        case unusable
    }

    /// Why the last decryption attempt failed.
    private enum DecryptFailure {
        case missingKey
        case lookupFailed
        case code(Int)
    }

    private final class PendingOperation {
        let name: String
        let key: String
        let run: () -> Outcome
        let lost: (() -> Outcome)?
        let complete: ((Outcome) -> Void)?
        /// The per-launch sweep, queued by the vault itself and not by the app.
        let isSweep: Bool
        var wasParked = false
        var confirmedLockedAttempts = 0
        var lastCountedTick: Int?

        init(name: String, key: String, run: @escaping () -> Outcome, lost: (() -> Outcome)?, complete: ((Outcome) -> Void)?, isSweep: Bool = false) {
            self.name = name
            self.key = key
            self.run = run
            self.lost = lost
            self.complete = complete
            self.isSweep = isSweep
        }
    }

    /// One copy of a key together with the service it lives in. Bundle id service copies always rank below `cap_sec` copies.
    private struct Source {
        let store: SecureStorageItemStore
        let copy: SecureStorageItemStore.Copy
        let isLegacyService: Bool
    }

    private typealias KeyCandidate = (tag: Data, secureEnclave: Bool)

    static let magic = Data([0x00, 0x53, 0x4B, 0x01])
    static let missingItemMessage = "Item with given key does not exist"
    static let unsupportedAccessibilityMessage = "Unsupported accessibility value"
    static let unsupportedConfigurationMessage = "Unsupported accessibility value in plugin configuration"
    static let storageErrorMessage = "error"
    static let removeFailedMessage = "Remove failed"
    /// Class of a plaintext value written because encryption failed.
    static let plaintextFallbackAccessibility = Accessibility.whenUnlockedThisDeviceOnly
    /// Retries after the first locked result seen while protected data is available, at most one per timer tick.
    static let lockedRetriesBeforeLost = 3
    /// Runs of the load sweep per process when keys had to be skipped.
    static let sweepAttempts = 3

    let queue = DispatchQueue(label: "capacitor-secure-storage-plugin.vault")
    let configuration: Configuration
    let dedicated: SecureStorageItemStore
    let standard: SecureStorageItemStore

    private static let keyLock = NSLock()
    private typealias CachedKey = (key: SecKey, secureEnclave: Bool)
    private static var cachedKeys: [Data: CachedKey] = [:]

    private let keyTag: Data
    private let keyCandidates: [KeyCandidate]
    private let bundleIdentifier: String?
    private let isProtectedDataAvailable: () -> Bool?
    private let isApplicationActive: () -> Bool
    private let refreshSignals: () -> Void
    private let unlockProbe: (() -> Bool)?
    private let ticker: SecureStorageTicker
    private let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private let logger = Logger(subsystem: "capacitor-secure-storage-plugin", category: "vault")
    private var parkedOperations: [PendingOperation] = []
    private var tickerRunning = false
    private var tickCount = 0
    private var accessGroupMode: AccessGroupMode?
    private var sweepRequested = false
    private var sweepQueued = false
    private var sweepRuns = 0
    /// The sweep waits until `sweepQuietPeriod` passed after a completed app call without another one, or until the backstop
    /// after a request fired, so on a cold start it never runs ahead of the app's first call or between two of its calls.
    /// Every app call closes it again.
    private var sweepGateOpen = false
    private var sweepBackstopScheduled = false
    private var sweepQuietPeriod: DispatchTimeInterval = .milliseconds(1500)
    /// Bumped when an app call is queued and when it completes. A quiet check opens the gate only when it is unchanged.
    private var appCallGeneration = 0
    private var lastAppCall: DispatchTime?
    private var sweepBody: (SecureStorageVault) -> Bool = { $0.runSweep() }
    /// -25308 results of the key, and its lookups or decryptions that failed for a reason not known to be permanent, while
    /// the device was confirmed unlocked, at most one per tick, reset by a working key.
    private var keyRefusals = 0
    private var lastKeyRefusalTick: Int?
    /// Set once the key kept refusing or failing, for the rest of the process. The vault never deletes the key itself.
    private var keyUnusable = false
    /// Set while a call runs again after one of its runs counted towards the lost escape: decryption makes a single attempt
    /// without `decryptRetryDelays`, so the retries on timer ticks do not hold the queue.
    private var singleDecryptAttempt = false
    /// Only read or written on `queue`.
    private(set) var counters = Counters()
    /// Test hook for the plaintext fallback: encryption reports a non-lock failure. Set on `queue` only.
    var simulatesEncryptionFailure = false
    /// Test hooks in place of `SecItemCopyMatching` for the key lookup and `SecKeyCreateDecryptedData`. Set on `queue` only.
    var copyMatchingKey: (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus = SecItemCopyMatching
    var decryptCiphertext: (SecKey, SecKeyAlgorithm, CFData, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? = SecKeyCreateDecryptedData
    /// Waits before the second and third decryption attempt. Set on `queue` only.
    var decryptRetryDelays: [TimeInterval] = [0.05, 0.2]

    /// - Parameters:
    ///   - bundleIdentifier: builds the app-private access group `<TEAM>.<bundle id>`. `nil` keeps the default group.
    ///   - isProtectedDataAvailable: cheap pre-check, `nil` while not known yet. Unknown counts as available and the keychain's
    ///     own `errSecInteractionNotAllowed` decides.
    ///   - isApplicationActive: the load sweep waits for the app to be in the foreground.
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
        bundleIdentifier: String? = Bundle.main.bundleIdentifier,
        isProtectedDataAvailable: @escaping () -> Bool? = { true },
        isApplicationActive: @escaping () -> Bool = { true },
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
        self.bundleIdentifier = bundleIdentifier
        self.isProtectedDataAvailable = isProtectedDataAvailable
        self.isApplicationActive = isApplicationActive
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
            self.noteAppCall()
            self.parkedOperations.append(operation)
            self.runParkedOperations()
        }
    }

    func drainParkedOperations() {
        queue.async {
            self.runParkedOperations()
        }
    }

    /// Asks for the per-launch sweep. It is queued behind the app's calls once `quietPeriod` passed after a completed app call
    /// without another app call, the queue has drained, the app is in the foreground and protected data is known to be
    /// available. When the app makes no call, the request opens that gate after `backstop` instead, later while an app call
    /// came within the last `quietPeriod`. `body` replaces the keychain sweep in tests and returns `false` when keys were
    /// skipped and the sweep should run again later.
    func requestSweep(backstop: DispatchTimeInterval = .seconds(5), quietPeriod: DispatchTimeInterval = .milliseconds(1500), _ body: ((SecureStorageVault) -> Bool)? = nil) {
        queue.async {
            if let body = body {
                self.sweepBody = body
            }
            self.sweepQuietPeriod = quietPeriod
            self.sweepRequested = true
            if !self.sweepGateOpen, !self.sweepBackstopScheduled {
                self.sweepBackstopScheduled = true
                self.queue.asyncAfter(deadline: .now() + backstop) { [weak self] in
                    self?.fireSweepBackstop()
                }
            }
            self.runParkedOperations()
        }
    }

    /// Opens the gate unless an app call came within the last quiet period, then it checks again once that has passed.
    private func fireSweepBackstop() {
        if !sweepGateOpen, let last = lastAppCall, DispatchTime.now() < last + sweepQuietPeriod {
            queue.asyncAfter(deadline: last + sweepQuietPeriod) { [weak self] in
                self?.fireSweepBackstop()
            }
            return
        }
        sweepBackstopScheduled = false
        guard !sweepGateOpen else { return }
        sweepGateOpen = true
        runParkedOperations()
    }

    /// An app call was queued or completed. The sweep gate stays closed until the next quiet period.
    private func noteAppCall() {
        appCallGeneration += 1
        lastAppCall = .now()
        sweepGateOpen = false
    }

    /// After a completed app call: opens the gate once `sweepQuietPeriod` passed without another app call, then drains.
    private func scheduleQuietCheck() {
        guard sweepRequested else { return }
        let generation = appCallGeneration
        queue.asyncAfter(deadline: .now() + sweepQuietPeriod) { [weak self] in
            guard let self = self, self.appCallGeneration == generation else { return }
            self.sweepGateOpen = true
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

    /// `<TEAM>.<bundle id>`, the team prefix taken before the first `.` of the group the keychain picked for a throwaway item.
    static func appPrivateGroup(defaultGroup: String, bundleIdentifier: String?) -> String? {
        guard let dot = defaultGroup.firstIndex(of: "."), dot != defaultGroup.startIndex else { return nil }
        guard let bundle = bundleIdentifier, !bundle.isEmpty else { return nil }
        return "\(defaultGroup[..<dot]).\(bundle)"
    }

    /// Resolves and caches the app-private access group. `nil` means the keychain is locked and the caller should park.
    func resolveAccessGroup() -> AccessGroupMode? {
        if let mode = accessGroupMode {
            return mode
        }
        let probeService = dedicated.service + ".probe"
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: probeService] as CFDictionary)
        func probe(_ group: String?) -> (status: OSStatus, group: String?) {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: probeService,
                kSecAttrAccount as String: Data("group.\(UUID().uuidString)".utf8),
                kSecAttrSynchronizable as String: false,
            ]
            if let group = group {
                query[kSecAttrAccessGroup as String] = group
            }
            var add = query
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            add[kSecValueData as String] = Data()
            add[kSecReturnAttributes as String] = true
            var result: CFTypeRef?
            let status = SecItemAdd(add as CFDictionary, &result)
            if status == errSecSuccess {
                SecItemDelete(query as CFDictionary)
            }
            return (status, (result as? [String: Any])?[kSecAttrAccessGroup as String] as? String)
        }
        let throwaway = probe(nil)
        if throwaway.status == errSecInteractionNotAllowed {
            return nil
        }
        guard throwaway.status == errSecSuccess, let defaultGroup = throwaway.group else {
            return fallBackToDefaultGroup(nil, reason: "throwaway item \(throwaway.status)")
        }
        guard let explicitGroup = SecureStorageVault.appPrivateGroup(defaultGroup: defaultGroup, bundleIdentifier: bundleIdentifier) else {
            return fallBackToDefaultGroup(defaultGroup, reason: "no team prefix or bundle id")
        }
        if explicitGroup != defaultGroup {
            let check = probe(explicitGroup)
            if check.status == errSecInteractionNotAllowed {
                return nil
            }
            guard check.status == errSecSuccess else {
                return fallBackToDefaultGroup(defaultGroup, reason: "explicit group \(check.status)")
            }
        }
        let mode = AccessGroupMode(explicitGroup: explicitGroup, defaultGroup: defaultGroup)
        accessGroupMode = mode
        logger.notice("access group explicit")
        return mode
    }

    func storeValue(_ value: String, forKey key: String, accessibility: Accessibility? = nil) -> Outcome {
        guard let mode = resolveAccessGroup() else { return .locked }
        var itemClass = accessibility ?? configuration.accessibility
        var isFallback = false
        let data: Data
        switch encodeValue(value) {
        case .encoded(let encoded):
            data = encoded
        case .locked:
            return .locked
        case .failure:
            // Rejecting would read as a missing key in the app. Store plaintext with the strict class instead.
            data = Data(value.utf8)
            itemClass = itemClass.tightened(toAtLeast: SecureStorageVault.plaintextFallbackAccessibility)
            isFallback = true
        }
        let write = writeToTarget(key, data: data, accessibility: itemClass.attribute, mode: mode)
        switch classifyStatus(write.status, context: "write \(key)") {
        case .ok:
            if isFallback {
                counters.plaintextFallbacks += 1
                logger.fault("stored \(key, privacy: .public) as plaintext \(itemClass.rawValue, privacy: .public), encryption unavailable")
            }
            removeStaleCopies(of: key, keeping: write.group)
            return .resolve(["value": true])
        case .locked:
            return .locked
        case .notFound, .failed:
            return .reject(SecureStorageVault.storageErrorMessage, code: .storageError)
        }
    }

    /// `set` for an item the keychain keeps refusing while unlocked: drop every copy, then write a fresh one.
    func replaceLostValue(_ value: String, forKey key: String, accessibility: Accessibility? = nil) -> Outcome {
        _ = classifyStatus(dedicated.deleteItem(key), context: "delete lost \(key)")
        _ = classifyStatus(standard.deleteItem(key), context: "delete lost standard \(key)")
        return storeValue(value, forKey: key, accessibility: accessibility)
    }

    func loadValue(forKey key: String) -> Outcome {
        switch settleKey(key, includeLegacyService: false, migrate: isProtectedDataAvailable() != false) {
        case .value(let value):
            return .resolve(["value": value])
        case .missing:
            return .reject(SecureStorageVault.missingItemMessage, code: .notFound)
        case .locked:
            return .locked
        case .unreadable:
            // The item stays in place and a `set` overwrites it.
            return .reject(SecureStorageVault.missingItemMessage, code: .unreadable)
        case .failure:
            return .reject(SecureStorageVault.storageErrorMessage, code: .storageError)
        }
    }

    /// `get` for an item the keychain keeps refusing while unlocked.
    func lostValue(forKey key: String) -> Outcome {
        return .reject(SecureStorageVault.missingItemMessage, code: .unreadable)
    }

    func listStoredKeys() -> Outcome {
        let list = dedicated.listKeys()
        switch classifyStatus(list.status, context: "list") {
        case .ok, .notFound:
            return .resolve(["value": list.keys])
        case .locked:
            return .locked
        case .failed:
            return .reject(SecureStorageVault.storageErrorMessage, code: .storageError)
        }
    }

    /// `keys` while the keychain keeps refusing the listing although the device is unlocked.
    func lostKeyList() -> Outcome {
        return .resolve(["value": [String]()])
    }

    func removeValue(forKey key: String) -> Outcome {
        var existed = false
        for store in [dedicated, standard] {
            let found = store.copies(of: key)
            switch classifyStatus(found.status, context: "find \(key) in \(store.service) before remove") {
            case .ok, .notFound:
                existed = existed || !found.copies.isEmpty
            case .failed:
                existed = true
            case .locked:
                return .locked
            }
        }
        guard existed else { return .reject(SecureStorageVault.missingItemMessage, code: .notFound) }
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
        return removed ? .resolve(["value": true]) : .reject(SecureStorageVault.removeFailedMessage, code: .storageError)
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
        return cleared ? .resolve(["value": true]) : .reject(SecureStorageVault.storageErrorMessage, code: .storageError)
    }

    /// `clear` while the keychain keeps refusing it although the device is unlocked.
    func removeAllLostValues() -> Outcome {
        _ = classifyStatus(dedicated.deleteAll(), context: "clear lost")
        return .resolve(["value": true])
    }

    /// The load sweep: settles every `cap_sec` key (group, class, encoding, duplicates, bundle id copy). Resolves with
    /// `skipped`, the number of keys that were locked and need another run. Never runs while protected data is unavailable.
    func migrateLegacyValues() -> Outcome {
        guard isProtectedDataAvailable() != false else {
            logger.notice("sweep skipped while protected data is unavailable")
            return .resolve(["skipped": 1])
        }
        let list = dedicated.listKeys()
        switch classifyStatus(list.status, context: "list for sweep") {
        case .ok, .notFound:
            return migrateKeys(list.keys) { key in
                switch self.settleKey(key, includeLegacyService: true, migrate: true) {
                case .locked:
                    return .locked
                case .failure:
                    return .reject(SecureStorageVault.storageErrorMessage, code: .storageError)
                case .value, .missing, .unreadable:
                    return .resolve([:])
                }
            }
        case .locked:
            logger.notice("sweep skipped while locked")
            return .resolve(["skipped": 1])
        case .failed:
            return .reject(SecureStorageVault.storageErrorMessage, code: .storageError)
        }
    }

    func migrateKeys(_ keys: [String], using migrate: (String) -> Outcome) -> Outcome {
        var skipped = 0
        for key in keys {
            if case .locked = migrate(key) {
                skipped += 1
                logger.notice("sweep skipped \(key, privacy: .public) while locked")
            }
        }
        return .resolve(["skipped": skipped])
    }

    /// Reads a key across all of its copies. The `cap_sec` copy that `rank` puts first wins. The bundle id service only
    /// counts when `cap_sec` has none (or for cleanup with `includeLegacyService`). With `migrate` it writes the winner into
    /// the target group with the target class and encoding, reads it back and verifies it, and only then deletes every
    /// other copy.
    func settleKey(_ key: String, includeLegacyService: Bool, migrate: Bool) -> SettleResult {
        guard let mode = resolveAccessGroup() else { return .locked }
        let found = dedicated.copies(of: key)
        switch classifyStatus(found.status, context: "find \(key)") {
        case .ok, .notFound:
            break
        case .locked:
            return .locked
        case .failed:
            return .failure
        }
        guard var sources = rank(found.copies, of: key, in: dedicated, legacy: false, target: mode.targetGroup) else { return .locked }
        if sources.isEmpty || includeLegacyService {
            let legacy = standard.copies(of: key)
            switch classifyStatus(legacy.status, context: "find standard \(key)") {
            case .ok, .notFound:
                if let ranked = rank(legacy.copies, of: key, in: standard, legacy: true, target: nil) {
                    sources += ranked
                } else if sources.isEmpty {
                    return .locked
                }
            case .locked where sources.isEmpty:
                return .locked
            case .failed where sources.isEmpty:
                return .failure
            case .locked, .failed:
                break
            }
        }
        guard let chosen = sources.first else { return .missing }
        let read = chosen.store.readItem(key, accessGroup: chosen.copy.accessGroup)
        switch classifyStatus(read.status, context: "read \(key)") {
        case .ok:
            break
        case .notFound:
            return .missing
        case .locked:
            return .locked
        case .failed:
            return .failure
        }
        let value: String
        switch decodeValue(read.data) {
        case .plaintext(let decoded), .decrypted(let decoded):
            value = decoded
        case .locked:
            return .locked
        case .invalid:
            counters.decryptFailures += 1
            logger.error("\(key, privacy: .public) cannot be decoded, reported as missing, other copies kept")
            if migrate {
                protectPlaintextCopies(of: key, in: sources)
            }
            return .unreadable
        }
        if migrate {
            migrateCopies(of: key, value: value, data: read.data, sources: sources, mode: mode)
        }
        return .value(value)
    }

    /// The winner `sources.first` cannot be decoded, so no other copy may replace it or be promoted over it. That would bring
    /// back a stale value. Older copies that are readable plaintext are encrypted and tightened in place instead, so their
    /// value does not sit in the clear in a weaker group or class until the next `set`. Only copies that keep ranking below
    /// the winner after the rewrite qualify: unmarked `cap_sec` copies (the rewrite leaves the label alone) and bundle id
    /// copies. A rewrite that does not read back is put back as it was.
    private func protectPlaintextCopies(of key: String, in sources: [Source]) {
        for source in sources.dropFirst() where source.isLegacyService || !source.copy.isMarked {
            guard let group = source.copy.accessGroup else { continue }
            let read = source.store.readCopy(source.copy, of: key)
            guard read.status == errSecSuccess, !isEncodedValue(read.data), let value = String(data: read.data, encoding: .utf8) else { continue }
            let currentClass = source.copy.accessibility.flatMap(Accessibility.init(attribute:))
            var targetClass = currentClass?.tightened(toAtLeast: configuration.accessibility) ?? configuration.accessibility
            var targetData = read.data
            var isFallback = false
            if configuration.encryptsValues {
                switch encodeValue(value) {
                case .encoded(let encoded):
                    targetData = encoded
                case .locked:
                    continue
                case .failure:
                    targetClass = targetClass.tightened(toAtLeast: SecureStorageVault.plaintextFallbackAccessibility)
                    isFallback = true
                }
            }
            guard targetData != read.data || currentClass != targetClass else { continue }
            let status = source.store.rewriteCopy(source.copy, of: key, data: targetData, accessibility: targetClass.attribute)
            guard case .ok = classifyStatus(status, context: "protect older copy of \(key)") else { continue }
            let check = source.store.readCopy(source.copy, of: key)
            guard check.status == errSecSuccess, decodes(check.data, to: value) else {
                _ = classifyStatus(source.store.restoreItem(key, data: read.data, accessibility: source.copy.accessibility, label: source.copy.label, accessGroup: group), context: "restore older copy of \(key)")
                logger.fault("older copy of \(key, privacy: .public) not verified, put back")
                continue
            }
            counters.migrated += 1
            if isFallback {
                counters.plaintextFallbacks += 1
            }
            logger.notice("protected an older copy of \(key, privacy: .public) in place, the newest copy cannot be decoded")
        }
    }

    func isEncodedValue(_ data: Data) -> Bool {
        return data.starts(with: SecureStorageVault.magic)
    }

    func encodeValue(_ value: String) -> EncodeResult {
        let plaintext = Data(value.utf8)
        guard configuration.encryptsValues else { return .encoded(plaintext) }
        guard !simulatesEncryptionFailure else { return .failure }
        let key: SecKey
        switch acquirePrivateKey(creating: true) {
        case .key(let acquired):
            key = acquired
        case .locked:
            return .locked
        case .missing, .failure, .unusable:
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
        // Ciphertext the key cannot open again would replace a readable value, so it is opened once before anyone writes it.
        switch decrypt(ciphertext, context: "encryption check") {
        case .plaintext(let decrypted) where decrypted == plaintext:
            return .encoded(SecureStorageVault.magic + ciphertext)
        case .plaintext:
            logger.fault("encryption check returned other bytes")
            return .failure
        case .locked:
            return .locked
        case .failed, .unusable:
            return .failure
        }
    }

    func decodeValue(_ data: Data) -> DecodeResult {
        guard isEncodedValue(data) else {
            guard let value = String(data: data, encoding: .utf8) else { return .invalid }
            return .plaintext(value)
        }
        let ciphertext = Data(data.dropFirst(SecureStorageVault.magic.count))
        // A prefix without ciphertext is broken whatever key or retry, so is plaintext that is not UTF-8.
        guard !ciphertext.isEmpty else { return .invalid }
        switch decrypt(ciphertext, context: "decrypt") {
        case .plaintext(let plaintext):
            guard let value = String(data: plaintext, encoding: .utf8) else { return .invalid }
            return .decrypted(value)
        case .locked, .failed(.lookupFailed):
            return .locked
        case .failed(.missingKey), .unusable:
            return .invalid
        case .failed(.code(let code)):
            // Only a wrong key or corrupt ciphertext is final. Anything else parks and the tick-bounded key count or the lost
            // escape decides.
            guard SecureStorageVault.isPermanentDecryptFailure(code) else {
                logger.error("decrypt failure \(code, privacy: .public) is not known to be permanent, parked")
                return .locked
            }
            return .invalid
        }
    }

    /// `errSecParam` or `errSecDecode` after the retries: a wrong key or corrupt ciphertext, final for that ciphertext.
    private static func isPermanentDecryptFailure(_ code: Int) -> Bool {
        return code == Int(errSecParam) || code == Int(errSecDecode)
    }

    /// Decrypts with the key under the tag and never creates one, because a new key cannot open old ciphertext. When a
    /// decryption fails while the device is known to be unlocked, it drops the cached key, looks the key up again and
    /// retries after each of `decryptRetryDelays`. Only a call that runs again after counting towards the lost escape makes
    /// a single attempt. `.failed` is what still fails afterwards while the unlock probe confirms an unlocked device, or a
    /// key lookup that failed. A -25308 counts towards `noteKeyRefusal` like one from the key lookup. So do a failed key
    /// lookup and a failure that is not known to be permanent, so a key that keeps failing ends as unusable for the process
    /// instead of parking every call for its own lost escape. Such a failure only makes the key unusable when the key
    /// cannot open fresh ciphertext either.
    private func decrypt(_ ciphertext: Data, context: String) -> DecryptResult {
        let delays = singleDecryptAttempt ? [] : decryptRetryDelays
        var failure = DecryptFailure.missingKey
        var lastKey: SecKey?
        for attempt in 0...delays.count {
            if attempt > 0 {
                counters.decryptRetries += 1
                Thread.sleep(forTimeInterval: delays[attempt - 1])
                forgetCachedKey()
            }
            let key: SecKey
            // A key found by the fresh lookup of a retry does not show that it decrypts, so that lookup keeps the count.
            switch acquirePrivateKey(creating: false, resettingRefusals: attempt == 0) {
            case .key(let acquired):
                key = acquired
            case .missing where attempt == 0:
                return isLockedFailure(code: Int(errSecItemNotFound), context: "\(context) without key") ? .locked : .failed(.missingKey)
            case .missing:
                // The key was there a moment ago. Give the lookup the remaining attempts.
                failure = .missingKey
                continue
            case .locked:
                return .locked
            case .failure:
                return noteKeyRefusal() ? .unusable : .failed(.lookupFailed)
            case .unusable:
                return .unusable
            }
            lastKey = key
            var error: Unmanaged<CFError>?
            if let plaintext = decryptCiphertext(key, algorithm, ciphertext as CFData, &error) as Data? {
                if attempt > 0 {
                    logger.notice("\(context, privacy: .public) succeeded on attempt \(attempt + 1, privacy: .public)")
                }
                keyRefusals = 0
                return .plaintext(plaintext)
            }
            let code = extractCode(from: error)
            if code == Int(errSecInteractionNotAllowed) {
                logger.notice("\(context, privacy: .public) locked \(code, privacy: .public)")
                return noteKeyRefusal() ? .unusable : .locked
            }
            if isProtectedDataAvailable() != true {
                logger.notice("\(context, privacy: .public) locked \(code, privacy: .public)")
                return .locked
            }
            logger.notice("\(context, privacy: .public) attempt \(attempt + 1, privacy: .public) failed \(code, privacy: .public)")
            failure = .code(code)
        }
        let code: Int
        switch failure {
        case .missingKey:
            code = Int(errSecItemNotFound)
        case .lookupFailed:
            return .failed(failure)
        case .code(let failed):
            code = failed
        }
        if isLockedFailure(code: code, context: context) {
            return .locked
        }
        if case .code(let failed) = failure, !SecureStorageVault.isPermanentDecryptFailure(failed), noteKeyRefusal(unlessDecryptedBy: lastKey) {
            return .unusable
        }
        return .failed(failure)
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

    private func fallBackToDefaultGroup(_ defaultGroup: String?, reason: String) -> AccessGroupMode {
        let mode = AccessGroupMode(explicitGroup: nil, defaultGroup: defaultGroup)
        if accessGroupMode?.isExplicit != false {
            logger.error("access group fallback to the default group: \(reason, privacy: .public)")
        }
        accessGroupMode = mode
        return mode
    }

    /// Writes into the target group. A missing entitlement for the explicit group switches to the default group for good.
    private func writeToTarget(_ key: String, data: Data, accessibility: CFString, mode: AccessGroupMode) -> (status: OSStatus, group: String?) {
        let status = dedicated.writeItem(key, data: data, accessibility: accessibility, accessGroup: mode.targetGroup)
        guard mode.isExplicit, status == errSecMissingEntitlement || status == errSecParam else {
            return (status, mode.targetGroup)
        }
        let fallback = fallBackToDefaultGroup(mode.defaultGroup, reason: "write \(status)")
        return (dedicated.writeItem(key, data: data, accessibility: accessibility, accessGroup: fallback.targetGroup), fallback.targetGroup)
    }

    /// After a successful `set` into `group`, other copies of the key hold an older value.
    private func removeStaleCopies(of key: String, keeping group: String?) {
        guard let group = group else { return }
        var removed = 0
        let found = dedicated.copies(of: key)
        if found.status == errSecSuccess {
            for copy in found.copies where copy.accessGroup != group {
                if case .ok = classifyStatus(dedicated.deleteCopy(copy, of: key), context: "delete stale \(key)") {
                    removed += 1
                }
            }
        }
        let legacy = standard.copies(of: key)
        if legacy.status == errSecSuccess {
            for copy in legacy.copies {
                if case .ok = classifyStatus(standard.deleteCopy(copy, of: key), context: "delete stale standard \(key)") {
                    removed += 1
                }
            }
        }
        counters.duplicatesResolved += removed
    }

    /// Orders the copies of a key in one service, the winner first. Copies this version wrote (marked) come first, the newest
    /// of them first. When no copy is marked, the copy upstream 0.13.0 read wins, so the first read after the upgrade returns
    /// the value the app has been using: SwiftKeychainWrapper's query without a group and limit one decides, not the
    /// modification date, which can belong to another copy. `nil` when that query hits a locked keychain.
    private func rank(_ copies: [SecureStorageItemStore.Copy], of key: String, in store: SecureStorageItemStore, legacy: Bool, target: String?) -> [Source]? {
        var sorted = copies.enumerated().sorted { lhs, rhs in
            if lhs.element.isMarked != rhs.element.isMarked {
                return lhs.element.isMarked
            }
            let left = lhs.element.modified ?? .distantPast
            let right = rhs.element.modified ?? .distantPast
            if left != right {
                return left > right
            }
            let leftInTarget = target != nil && lhs.element.accessGroup == target
            let rightInTarget = target != nil && rhs.element.accessGroup == target
            if leftInTarget != rightInTarget {
                return leftInTarget
            }
            return lhs.offset < rhs.offset
        }.map { $0.element }
        if sorted.count > 1, !sorted.contains(where: { $0.isMarked }) {
            let upstream = store.upstreamCopyReference(of: key)
            switch classifyStatus(upstream.status, context: "upstream read of \(key) in \(store.service)") {
            case .ok:
                if let reference = upstream.reference, let index = sorted.firstIndex(where: { $0.persistentRef == reference }) {
                    sorted.insert(sorted.remove(at: index), at: 0)
                } else {
                    logger.error("upstream copy of \(key, privacy: .public) is not among the listed copies, newest copy first")
                }
            case .locked:
                return nil
            case .notFound, .failed:
                break
            }
        }
        return sorted.map { Source(store: store, copy: $0, isLegacyService: legacy) }
    }

    /// The migration unit for one key. `sources` are ranked, the first one holds `value` as `data`.
    private func migrateCopies(of key: String, value: String, data: Data, sources: [Source], mode: AccessGroupMode) {
        guard let chosen = sources.first else { return }
        let targetGroup = mode.targetGroup ?? (chosen.isLegacyService ? nil : chosen.copy.accessGroup)
        let isTargetCopy: (Source) -> Bool = { source in
            !source.isLegacyService && (targetGroup == nil ? source.copy.persistentRef == chosen.copy.persistentRef : source.copy.accessGroup == targetGroup)
        }
        let currentClass = chosen.copy.accessibility.flatMap(Accessibility.init(attribute:))
        // A class chosen by a `set` of this version stays, legacy items are tightened to at least the configured class.
        let keepsClass = chosen.copy.isMarked && !chosen.isLegacyService
        var targetClass = (keepsClass ? currentClass : currentClass?.tightened(toAtLeast: configuration.accessibility)) ?? configuration.accessibility
        var targetData = data
        var isFallback = false
        if configuration.encryptsValues && !isEncodedValue(data) {
            switch encodeValue(value) {
            case .encoded(let encoded):
                targetData = encoded
            case .locked:
                logger.notice("migration of \(key, privacy: .public) postponed, encryption locked")
                return
            case .failure:
                // Same rule as `set`: plaintext stays, but with the strict class.
                targetClass = targetClass.tightened(toAtLeast: SecureStorageVault.plaintextFallbackAccessibility)
                isFallback = true
            }
        }
        let others = sources.filter { !isTargetCopy($0) }
        let needsWrite = !isTargetCopy(chosen) || targetData != data || currentClass != targetClass
        guard needsWrite || !others.isEmpty else { return }
        var added = 0
        var conflicting = 0
        if needsWrite {
            let target = sources.first(where: isTargetCopy)
            // What the target copy holds now, so a write that does not verify can be put back.
            var original: (data: Data, accessibility: String?, label: String?, group: String)?
            var overwritten: Data?
            let status: OSStatus
            if let target = target {
                guard let group = target.copy.accessGroup else { return }
                if !chosen.isLegacyService && chosen.copy.accessGroup == group {
                    original = (data, chosen.copy.accessibility, chosen.copy.label, group)
                } else {
                    let read = dedicated.readCopy(target.copy, of: key)
                    guard case .ok = classifyStatus(read.status, context: "read target copy of \(key)") else { return }
                    original = (read.data, target.copy.accessibility, target.copy.label, group)
                    overwritten = read.data
                }
                status = dedicated.updateItem(key, data: targetData, accessibility: targetClass.attribute, accessGroup: group)
            } else {
                status = dedicated.addItem(key, data: targetData, accessibility: targetClass.attribute, accessGroup: targetGroup)
                if status == errSecDuplicateItem {
                    // A copy the listing did not return sits in the target group. It is not overwritten, because nothing could
                    // put it back, and the next run lists the copies again.
                    logger.notice("migration of \(key, privacy: .public) postponed, unlisted copy in the target group")
                    return
                }
                if status == errSecSuccess {
                    added = 1
                }
            }
            if mode.isExplicit, status == errSecMissingEntitlement || status == errSecParam {
                _ = fallBackToDefaultGroup(mode.defaultGroup, reason: "migration write \(status)")
                return
            }
            guard case .ok = classifyStatus(status, context: "migration write \(key)") else { return }
            guard verify(key, value: value, in: original?.group ?? targetGroup) else {
                // Put the copies back as they were: the old data, class and label of the target copy, or delete the added copy
                // so the copy that was read stays the newest.
                if let original = original {
                    _ = classifyStatus(dedicated.restoreItem(key, data: original.data, accessibility: original.accessibility, label: original.label, accessGroup: original.group), context: "restore \(key) after an unverified migration")
                } else {
                    removeAddedCopies(of: key, besides: sources)
                }
                logger.fault("migration of \(key, privacy: .public) not verified, write undone, other copies kept")
                return
            }
            counters.migrated += 1
            if isFallback {
                counters.plaintextFallbacks += 1
                logger.fault("migrated \(key, privacy: .public) as plaintext \(targetClass.rawValue, privacy: .public), encryption unavailable")
            }
            if let overwritten = overwritten, holdsAnotherValue(overwritten, than: value) {
                conflicting += 1
            }
        }
        var deleted = 0
        for (index, source) in sources.enumerated() where !isTargetCopy(source) {
            // The winner holds `value`, every other copy is read before it goes.
            let differs = index > 0 && holdsAnotherValue(source, of: key, than: value)
            if case .ok = classifyStatus(source.store.deleteCopy(source.copy, of: key), context: "delete migrated copy of \(key)") {
                deleted += 1
                conflicting += differs ? 1 : 0
            }
        }
        counters.duplicatesResolved += max(0, deleted - added)
        counters.conflictingDuplicates += conflicting
        if conflicting > 0 {
            logger.notice("settled \(key, privacy: .public) over \(conflicting, privacy: .public) copies with another value")
        }
        logger.notice("settled \(key, privacy: .public) wrote \(needsWrite, privacy: .public) removed \(deleted, privacy: .public)")
    }

    /// True when a copy decodes to another value than the winner. A copy that cannot be read or decoded is not counted.
    private func holdsAnotherValue(_ source: Source, of key: String, than value: String) -> Bool {
        let read = source.store.readCopy(source.copy, of: key)
        guard read.status == errSecSuccess else { return false }
        return holdsAnotherValue(read.data, than: value)
    }

    private func holdsAnotherValue(_ data: Data, than value: String) -> Bool {
        switch decodeValue(data) {
        case .plaintext(let decoded), .decrypted(let decoded):
            return decoded != value
        case .locked, .invalid:
            return false
        }
    }

    /// Deletes the `cap_sec` copies of a key that are not among `sources`, the ones a migration write just added.
    private func removeAddedCopies(of key: String, besides sources: [Source]) {
        let known = Set(sources.filter { !$0.isLegacyService }.compactMap { $0.copy.persistentRef })
        let found = dedicated.copies(of: key)
        guard case .ok = classifyStatus(found.status, context: "find added copy of \(key)") else { return }
        for copy in found.copies {
            guard let reference = copy.persistentRef, !known.contains(reference) else { continue }
            _ = classifyStatus(dedicated.deleteCopy(copy, of: key), context: "delete added copy of \(key)")
        }
    }

    private func verify(_ key: String, value: String, in group: String?) -> Bool {
        let read = dedicated.readItem(key, accessGroup: group)
        guard read.status == errSecSuccess else { return false }
        return decodes(read.data, to: value)
    }

    private func decodes(_ data: Data, to value: String) -> Bool {
        switch decodeValue(data) {
        case .plaintext(let decoded), .decrypted(let decoded):
            return decoded == value
        case .locked, .invalid:
            return false
        }
    }

    private func runSweep() -> Bool {
        guard case .resolve(let data) = migrateLegacyValues() else { return false }
        return (data["skipped"] as? Int ?? 0) == 0
    }

    private func runParkedOperations() {
        runQueue()
        if parkedOperations.isEmpty, enqueueSweepIfDue() {
            runQueue()
        }
        updateTicker()
    }

    private func runQueue() {
        let operations = parkedOperations
        var remaining: [PendingOperation] = []
        for (index, operation) in operations.enumerated() {
            guard executeOperation(operation) else {
                remaining = Array(operations[index...])
                break
            }
        }
        parkedOperations = remaining
    }

    private func enqueueSweepIfDue() -> Bool {
        guard sweepRequested, sweepGateOpen, !sweepQueued, sweepRuns < SecureStorageVault.sweepAttempts else { return false }
        guard isApplicationActive(), isProtectedDataAvailable() == true else { return false }
        sweepRequested = false
        sweepQueued = true
        sweepRuns += 1
        let body = sweepBody
        parkedOperations.append(PendingOperation(name: "sweep", key: "*", run: { [unowned self] in
            let completed = body(self)
            self.sweepQueued = false
            if !completed {
                self.sweepRequested = true
            }
            return .resolve([:])
        }, lost: { .resolve([:]) }, complete: nil, isSweep: true))
        return true
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
        singleDecryptAttempt = operation.confirmedLockedAttempts > 0
        defer { singleDecryptAttempt = false }
        var outcome = gated ? .locked : operation.run()
        if !gated, case .locked = outcome, isProtectedDataAvailable() == true, countLockedWhileUnlocked(operation) {
            counters.lostItems += 1
            logger.fault("lost \(operation.name, privacy: .public) \(operation.key, privacy: .public) after \(operation.confirmedLockedAttempts, privacy: .public) locked results while unlocked")
            outcome = operation.lost?() ?? .reject(SecureStorageVault.missingItemMessage, code: .unreadable)
            if case .locked = outcome {
                outcome = .reject(SecureStorageVault.storageErrorMessage, code: .storageError)
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
        if !operation.isSweep {
            // Not in this pass: the app's next call is often already on its way.
            noteAppCall()
            scheduleQuietCheck()
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

    /// Looks the key up by tag, the explicit group first. `creating` adds a new key when none exists, only encryption asks for that.
    /// A lookup refused with -25308 counts towards `noteKeyRefusal`, a key found by a lookup resets the count unless
    /// `resettingRefusals` is false.
    private func acquirePrivateKey(creating: Bool, resettingRefusals: Bool = true) -> KeyResult {
        guard !keyUnusable else { return .unusable }
        let found = lookUpOrCreateKey(creating: creating)
        if found.refused {
            return noteKeyRefusal() ? .unusable : .locked
        }
        if case .key = found.result, found.lookedUp, resettingRefusals {
            keyRefusals = 0
        }
        return found.result
    }

    /// Counts a -25308 of the key lookup or of a decryption, a failed key lookup during a decryption, or a decryption failure
    /// that is not known to be permanent, while protected data is available and the unlock probe agrees,
    /// at most once per timer tick, the way `countLockedWhileUnlocked` counts a call. After the first one and
    /// `lockedRetriesBeforeLost` more the key is unusable for the rest of the process, as after a Quick Start that carried
    /// the key item but not a working Secure Enclave key: encryption reports a failure, so `set` stores plaintext with the
    /// strict class, and ciphertext reads as invalid. The vault never deletes the key, because a misjudged transient would
    /// destroy every ciphertext. The next launch tries it again. True once the key is unusable.
    /// With `unlessDecryptedBy` the key first has to fail to open ciphertext made for it just now. A failure that belongs to
    /// one item must not make every other item unreadable. That call ends through its own lost escape instead.
    private func noteKeyRefusal(unlessDecryptedBy key: SecKey? = nil) -> Bool {
        guard !keyUnusable else { return true }
        guard lastKeyRefusalTick != tickCount, isProtectedDataAvailable() == true, confirmUnlocked() else { return false }
        lastKeyRefusalTick = tickCount
        keyRefusals += 1
        guard keyRefusals > SecureStorageVault.lockedRetriesBeforeLost else { return false }
        if let key = key, decryptsFreshCiphertext(key) {
            logger.error("key opens fresh ciphertext, the failure belongs to the item")
            keyRefusals = 0
            return false
        }
        keyUnusable = true
        logger.fault("key refused \(self.keyRefusals, privacy: .public) times while unlocked, unusable for this process")
        return true
    }

    /// Encrypts a few bytes for `key` and decrypts them once, without retries.
    private func decryptsFreshCiphertext(_ key: SecKey) -> Bool {
        let probe = Data("capacitor-secure-storage-plugin.probe".utf8)
        var encryptError: Unmanaged<CFError>?
        guard let publicKey = SecKeyCopyPublicKey(key), let ciphertext = SecKeyCreateEncryptedData(publicKey, algorithm, probe as CFData, &encryptError) else {
            logger.error("key check encryption failed \(self.extractCode(from: encryptError), privacy: .public)")
            return false
        }
        var decryptError: Unmanaged<CFError>?
        guard let plaintext = decryptCiphertext(key, algorithm, ciphertext, &decryptError) as Data? else {
            logger.error("key check decryption failed \(self.extractCode(from: decryptError), privacy: .public)")
            return false
        }
        return plaintext == probe
    }

    /// `refused` is a lookup that returned -25308, `lookedUp` a key that came from the keychain and not from the cache.
    private func lookUpOrCreateKey(creating: Bool) -> (result: KeyResult, refused: Bool, lookedUp: Bool) {
        let mode = SecureStorageVault.cachedKey(for: keyTag) == nil ? resolveAccessGroup() : nil
        let group = mode?.explicitGroup
        SecureStorageVault.keyLock.lock()
        defer { SecureStorageVault.keyLock.unlock() }
        if let cached = SecureStorageVault.cachedKeys[keyTag] {
            return (.key(cached.key), false, false)
        }
        // The explicit group first, then any group the app can access, so a key created before the group existed is reused.
        let lookups: [(candidate: KeyCandidate, group: String?)] = (group.map { group in keyCandidates.map { ($0, Optional(group)) } } ?? []) + keyCandidates.map { ($0, nil) }
        for lookup in lookups {
            var query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: lookup.candidate.tag,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true,
            ]
            if lookup.candidate.secureEnclave {
                query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            }
            if let group = lookup.group {
                query[kSecAttrAccessGroup as String] = group
            }
            var result: CFTypeRef?
            switch classifyStatus(copyMatchingKey(query as CFDictionary, &result), context: "key lookup") {
            case .ok:
                guard let reference = result, CFGetTypeID(reference) == SecKeyGetTypeID() else {
                    logger.error("key lookup returned no key reference")
                    return (.failure, false, false)
                }
                let key = reference as! SecKey
                SecureStorageVault.cachedKeys[keyTag] = (key, lookup.candidate.secureEnclave)
                return (.key(key), false, true)
            case .notFound:
                continue
            case .locked:
                return (.locked, true, false)
            case .failed:
                return (.failure, false, false)
            }
        }
        guard creating else { return (.missing, false, false) }
        guard mode != nil else {
            // The access group probe was locked. Without a resolved group the key would land in the wrong place.
            return (.locked, false, false)
        }
        for candidate in keyCandidates {
            switch generatePrivateKey(candidate, accessGroup: group) {
            case .key(let key):
                SecureStorageVault.cachedKeys[keyTag] = (key, candidate.secureEnclave)
                return (.key(key), false, false)
            case .locked:
                return (.locked, false, false)
            case .missing, .failure, .unusable:
                continue
            }
        }
        return (.failure, false, false)
    }

    /// The key follows the configured item class: `whenUnlockedThisDeviceOnly` unless the configuration asks for an
    /// after-first-unlock class, then `afterFirstUnlockThisDeviceOnly`.
    var keyAccessibility: CFString {
        return configuration.accessibility.requiresUnlock ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }

    private static func cachedKey(for tag: Data) -> CachedKey? {
        keyLock.lock()
        defer { keyLock.unlock() }
        return cachedKeys[tag]
    }

    /// Forgets the key reference after a failed decryption, so the next attempt looks the key up again. Also a test hook.
    func forgetCachedKey() {
        SecureStorageVault.keyLock.lock()
        SecureStorageVault.cachedKeys[keyTag] = nil
        SecureStorageVault.keyLock.unlock()
    }

    /// Access control of the key object this process holds, for tests. A key created in this process reports its creation
    /// class, a key looked up from the keychain may not (the simulator reports `cku;dacl(true)` for every looked-up key).
    func keyAccessControlDescription() -> String? {
        guard let cached = SecureStorageVault.cachedKey(for: keyTag), let attributes = SecKeyCopyAttributes(cached.key) as? [String: Any] else { return nil }
        return attributes[kSecAttrAccessControl as String].map { String(describing: $0) }
    }

    /// `secureEnclave`, `software` (simulator fallback), `unusable` once the key kept refusing while unlocked (see
    /// `noteKeyRefusal`), or `none` when no key exists or it cannot be looked up right now. Looks the key up but never
    /// creates one.
    func keyBackend() -> String {
        if keyUnusable {
            return "unusable"
        }
        if SecureStorageVault.cachedKey(for: keyTag) == nil {
            _ = acquirePrivateKey(creating: false)
        }
        guard let cached = SecureStorageVault.cachedKey(for: keyTag) else { return "none" }
        return cached.secureEnclave ? "secureEnclave" : "software"
    }

    /// Counters since the process started plus the key and access group in use. Runs on `queue` and never parks.
    func diagnostics() -> [String: Any] {
        return [
            "parked": counters.parked,
            "migrated": counters.migrated,
            "duplicatesResolved": counters.duplicatesResolved,
            "lostItems": counters.lostItems,
            "decryptFailures": counters.decryptFailures,
            "plaintextFallbacks": counters.plaintextFallbacks,
            "decryptRetries": counters.decryptRetries,
            "conflictingDuplicates": counters.conflictingDuplicates,
            "keyBackend": keyBackend(),
            "accessGroupMode": resolveAccessGroup()?.isExplicit == true ? "explicit" : "default",
        ]
    }

    /// What `getDiagnostics` resolves with when the plugin configuration is invalid and no vault exists.
    static let emptyDiagnostics: [String: Any] = [
        "parked": 0,
        "migrated": 0,
        "duplicatesResolved": 0,
        "lostItems": 0,
        "decryptFailures": 0,
        "plaintextFallbacks": 0,
        "decryptRetries": 0,
        "conflictingDuplicates": 0,
        "keyBackend": "none",
        "accessGroupMode": "default",
    ]

    private func generatePrivateKey(_ candidate: KeyCandidate, accessGroup: String?) -> KeyResult {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, keyAccessibility, .privateKeyUsage, &error) else {
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
        if let accessGroup = accessGroup {
            attributes[kSecAttrAccessGroup as String] = accessGroup
        }
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let code = extractCode(from: error)
            if accessGroup != nil, code == Int(errSecMissingEntitlement) || code == Int(errSecParam) {
                logger.error("key creation in the explicit group failed \(code, privacy: .public), using the default group")
                return generatePrivateKey(candidate, accessGroup: nil)
            }
            return isLockedFailure(code: code, context: "key creation secureEnclave \(candidate.secureEnclave)") ? .locked : .failure
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
        return isLockedFailure(code: extractCode(from: error), context: context)
    }

    /// A crypto or key failure only counts as permanent when protected data is known to be available and the unlock probe
    /// agrees. Everything else parks, because a wrong "permanent" here would surface as a missing key in the app.
    private func isLockedFailure(code: Int, context: String) -> Bool {
        if code == Int(errSecInteractionNotAllowed) || isProtectedDataAvailable() != true || !confirmUnlocked() {
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
