import XCTest
import Capacitor
@testable import SecureStoragePlugin

final class SecureStorageConfigurationTests: XCTestCase {
    func testAccessibilityMapsToKeychainClasses() {
        let expected: [(String, CFString, Bool)] = [
            ("whenUnlocked", kSecAttrAccessibleWhenUnlocked, true),
            ("whenUnlockedThisDeviceOnly", kSecAttrAccessibleWhenUnlockedThisDeviceOnly, true),
            ("afterFirstUnlock", kSecAttrAccessibleAfterFirstUnlock, false),
            ("afterFirstUnlockThisDeviceOnly", kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, false),
            ("whenPasscodeSetThisDeviceOnly", kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, true),
        ]
        for (rawValue, attribute, requiresUnlock) in expected {
            let accessibility = SecureStorageVault.Accessibility(rawValue: rawValue)
            XCTAssertEqual(accessibility?.attribute, attribute, rawValue)
            XCTAssertEqual(accessibility?.requiresUnlock, requiresUnlock, rawValue)
        }
    }

    func testConfigurationDefaultsAreHardened() {
        let configuration = SecureStorageVault.Configuration()
        XCTAssertEqual(configuration.accessibility, .whenUnlockedThisDeviceOnly)
        XCTAssertTrue(configuration.encryptsValues)
        let parsed = SecureStorageVault.Configuration(requestedAccessibility: nil, encryptsValues: true)
        XCTAssertEqual(parsed?.accessibility, .whenUnlockedThisDeviceOnly)
        XCTAssertEqual(parsed?.encryptsValues, true)
        let optedOut = SecureStorageVault.Configuration(requestedAccessibility: "afterFirstUnlock", encryptsValues: false)
        XCTAssertEqual(optedOut?.accessibility, .afterFirstUnlock)
        XCTAssertEqual(optedOut?.encryptsValues, false)
    }

    func testConfigurationParsesSupportedAccessibility() {
        let parsed = SecureStorageVault.Configuration(requestedAccessibility: "whenUnlockedThisDeviceOnly", encryptsValues: false)
        XCTAssertEqual(parsed?.accessibility, .whenUnlockedThisDeviceOnly)
        XCTAssertEqual(parsed?.encryptsValues, false)
    }

    func testConfigurationRejectsUnsupportedAccessibility() {
        for rawValue in ["always", "", "WhenUnlocked", "kSecAttrAccessibleWhenUnlocked", " afterFirstUnlock"] {
            XCTAssertNil(SecureStorageVault.Configuration(requestedAccessibility: rawValue, encryptsValues: true), rawValue)
        }
    }

    func testKeychainAttributeMapsBackToAccessibility() {
        for accessibility in SecureStorageVault.Accessibility.allCases {
            XCTAssertEqual(SecureStorageVault.Accessibility(attribute: accessibility.attribute as String), accessibility)
        }
        for attribute in ["dk", "dku", "", "aku2"] {
            XCTAssertNil(SecureStorageVault.Accessibility(attribute: attribute), attribute)
        }
    }

    func testTightenedCoversAllPairs() {
        let order: [SecureStorageVault.Accessibility] = [.afterFirstUnlock, .afterFirstUnlockThisDeviceOnly, .whenUnlocked, .whenUnlockedThisDeviceOnly, .whenPasscodeSetThisDeviceOnly]
        let expected: [[SecureStorageVault.Accessibility]] = [
            [.afterFirstUnlock, .afterFirstUnlockThisDeviceOnly, .whenUnlocked, .whenUnlockedThisDeviceOnly, .whenPasscodeSetThisDeviceOnly],
            [.afterFirstUnlockThisDeviceOnly, .afterFirstUnlockThisDeviceOnly, .whenUnlockedThisDeviceOnly, .whenUnlockedThisDeviceOnly, .whenPasscodeSetThisDeviceOnly],
            [.whenUnlocked, .whenUnlockedThisDeviceOnly, .whenUnlocked, .whenUnlockedThisDeviceOnly, .whenPasscodeSetThisDeviceOnly],
            [.whenUnlockedThisDeviceOnly, .whenUnlockedThisDeviceOnly, .whenUnlockedThisDeviceOnly, .whenUnlockedThisDeviceOnly, .whenPasscodeSetThisDeviceOnly],
            [.whenPasscodeSetThisDeviceOnly, .whenPasscodeSetThisDeviceOnly, .whenPasscodeSetThisDeviceOnly, .whenPasscodeSetThisDeviceOnly, .whenPasscodeSetThisDeviceOnly],
        ]
        XCTAssertEqual(Set(order), Set(SecureStorageVault.Accessibility.allCases))
        var checked = 0
        for (row, existing) in order.enumerated() {
            for (column, configured) in order.enumerated() {
                XCTAssertEqual(existing.tightened(toAtLeast: configured), expected[row][column], "\(existing.rawValue) + \(configured.rawValue)")
                checked += 1
            }
        }
        XCTAssertEqual(checked, 25)
    }

    func testRejectMessagesMatchOtherPlatforms() {
        XCTAssertEqual(SecureStorageVault.missingItemMessage, "Item with given key does not exist")
        XCTAssertEqual(SecureStorageVault.undecryptableItemMessage, "Item with given key could not be decrypted")
        XCTAssertEqual(SecureStorageVault.unsupportedAccessibilityMessage, "Unsupported accessibility value")
        XCTAssertEqual(SecureStorageVault.unsupportedConfigurationMessage, "Unsupported accessibility value in plugin configuration")
    }

    func testResolveAccessibilityFallsBackToConfiguredDefault() {
        let vault = SecureStorageVault(configuration: SecureStorageVault.Configuration(accessibility: .whenUnlockedThisDeviceOnly, encryptsValues: true))
        XCTAssertEqual(vault.resolveAccessibility(nil), .whenUnlockedThisDeviceOnly)
        XCTAssertEqual(vault.resolveAccessibility("afterFirstUnlock"), .afterFirstUnlock)
        XCTAssertNil(vault.resolveAccessibility("always"))
        XCTAssertNil(vault.resolveAccessibility(""))
    }
}

final class SecureStorageGateTests: XCTestCase {
    private final class EventLog {
        private let lock = NSLock()
        private var storage: [String] = []

        var events: [String] {
            lock.lock()
            defer { lock.unlock() }
            return storage
        }

        func record(_ event: String) {
            lock.lock()
            storage.append(event)
            lock.unlock()
        }
    }

    private final class Flag {
        private let lock = NSLock()
        private var storage: Bool
        private var readCount = 0

        init(_ value: Bool) {
            storage = value
        }

        var reads: Int {
            lock.lock()
            defer { lock.unlock() }
            return readCount
        }

        func read() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            readCount += 1
            return storage
        }

        func write(_ value: Bool) {
            lock.lock()
            storage = value
            lock.unlock()
        }
    }

    private func describe(_ outcome: SecureStorageVault.Outcome) -> String {
        switch outcome {
        case .resolve(let data): return "resolve \(data["value"].map { "\($0)" } ?? "-")"
        case .reject(let message, _): return "reject \(message)"
        case .locked: return "locked"
        }
    }

    private func settle(_ vault: SecureStorageVault) {
        vault.drainParkedOperations()
        vault.queue.sync {}
    }

    func testParkedOperationBlocksLaterOperationsAndSettlesOnce() {
        let vault = SecureStorageVault()
        let log = EventLog()
        var attempts = 0
        vault.submitOperation(named: "first", key: "k", run: {
            attempts += 1
            return attempts < 4 ? .locked : .resolve(["value": "one"])
        }, completion: { log.record("first \(self.describe($0))") })
        vault.submitOperation(named: "second", key: "k", run: { .resolve(["value": "two"]) }, completion: { log.record("second \(self.describe($0))") })
        vault.queue.sync {}
        XCTAssertTrue(log.events.isEmpty)
        XCTAssertEqual(vault.queue.sync { attempts }, 2)
        settle(vault)
        XCTAssertTrue(log.events.isEmpty)
        XCTAssertEqual(vault.queue.sync { attempts }, 3)
        settle(vault)
        XCTAssertEqual(log.events, ["first resolve one", "second resolve two"])
        vault.submitOperation(named: "third", key: "k", run: { .locked }, completion: { log.record("third \(self.describe($0))") })
        settle(vault)
        settle(vault)
        XCTAssertEqual(log.events, ["first resolve one", "second resolve two"])
    }

    func testDrainStopsAtFirstReparkedOperation() {
        let vault = SecureStorageVault()
        let log = EventLog()
        var runs: [String] = []
        var headReady = false
        var middleReady = false
        vault.submitOperation(named: "X", key: "x", run: { runs.append("X"); return headReady ? .resolve(["value": "x"]) : .locked }, completion: { log.record("X \(self.describe($0))") })
        vault.submitOperation(named: "Y", key: "y", run: { runs.append("Y"); return middleReady ? .resolve(["value": "y"]) : .locked }, completion: { log.record("Y \(self.describe($0))") })
        vault.submitOperation(named: "Z", key: "z", run: { runs.append("Z"); return .resolve(["value": "z"]) }, completion: { log.record("Z \(self.describe($0))") })
        vault.queue.sync {}
        XCTAssertTrue(log.events.isEmpty)
        XCTAssertTrue(vault.queue.sync { runs.allSatisfy { $0 == "X" } })
        vault.queue.sync { headReady = true }
        settle(vault)
        XCTAssertEqual(log.events, ["X resolve x"])
        XCTAssertFalse(vault.queue.sync { runs.contains("Z") })
        settle(vault)
        XCTAssertEqual(log.events, ["X resolve x"])
        vault.queue.sync { middleReady = true }
        settle(vault)
        settle(vault)
        XCTAssertEqual(log.events, ["X resolve x", "Y resolve y", "Z resolve z"])
        XCTAssertEqual(vault.queue.sync { runs.filter { $0 == "Z" }.count }, 1)
    }

    func testGateParksWithoutRunningWhenDefaultClassRequiresUnlock() {
        for accessibility in [SecureStorageVault.Accessibility.whenUnlocked, .whenUnlockedThisDeviceOnly, .whenPasscodeSetThisDeviceOnly] {
            let available = Flag(false)
            let vault = SecureStorageVault(configuration: SecureStorageVault.Configuration(accessibility: accessibility), isProtectedDataAvailable: { available.read() })
            let log = EventLog()
            vault.submitOperation(named: "A", key: "a", run: { log.record("run A"); return .resolve(["value": "a"]) }, completion: { log.record("A \(self.describe($0))") })
            vault.submitOperation(named: "B", key: "b", run: { log.record("run B"); return .resolve(["value": "b"]) }, completion: { log.record("B \(self.describe($0))") })
            vault.queue.sync {}
            XCTAssertTrue(log.events.isEmpty, accessibility.rawValue)
            XCTAssertGreaterThan(available.reads, 0, accessibility.rawValue)
            available.write(true)
            settle(vault)
            XCTAssertEqual(log.events, ["run A", "A resolve a", "run B", "B resolve b"], accessibility.rawValue)
        }
    }

    func testGateIsBypassedWhenDefaultClassIsAvailableAfterFirstUnlock() {
        for accessibility in [SecureStorageVault.Accessibility.afterFirstUnlock, .afterFirstUnlockThisDeviceOnly] {
            let available = Flag(false)
            let vault = SecureStorageVault(configuration: SecureStorageVault.Configuration(accessibility: accessibility), isProtectedDataAvailable: { available.read() })
            let log = EventLog()
            vault.submitOperation(named: "A", key: "a", run: { .resolve(["value": "a"]) }, completion: { log.record("A \(self.describe($0))") })
            vault.submitOperation(named: "B", key: "b", run: { .reject("nope") }, completion: { log.record("B \(self.describe($0))") })
            vault.queue.sync {}
            XCTAssertEqual(log.events, ["A resolve a", "B reject nope"], accessibility.rawValue)
            XCTAssertEqual(available.reads, 0, accessibility.rawValue)
        }
    }

    func testLockedOutcomeStillParksWhenGateIsBypassed() {
        let vault = SecureStorageVault(configuration: SecureStorageVault.Configuration(accessibility: .afterFirstUnlock), isProtectedDataAvailable: { false })
        let log = EventLog()
        var locked = true
        vault.submitOperation(named: "A", key: "a", run: { locked ? .locked : .resolve(["value": "a"]) }, completion: { log.record("A \(self.describe($0))") })
        vault.submitOperation(named: "B", key: "b", run: { .resolve(["value": "b"]) }, completion: { log.record("B \(self.describe($0))") })
        vault.queue.sync {}
        XCTAssertTrue(log.events.isEmpty)
        vault.queue.sync { locked = false }
        settle(vault)
        XCTAssertEqual(log.events, ["A resolve a", "B resolve b"])
    }
}

final class SecureStorageSweepTests: XCTestCase {
    func testSweepSkipsLockedKeysAndContinues() {
        let vault = SecureStorageVault(configuration: SecureStorageVault.Configuration(accessibility: .whenUnlockedThisDeviceOnly, encryptsValues: true))
        var attempted: [String] = []
        let outcome = vault.migrateKeys(["a", "b", "c"]) { key in
            attempted.append(key)
            return key == "b" ? .locked : .resolve([:])
        }
        XCTAssertEqual(attempted, ["a", "b", "c"])
        guard case .resolve = outcome else {
            return XCTFail("sweep parked on a locked key")
        }
    }

    func testSweepWithoutEncryptionDoesNotTouchTheKeychain() {
        let vault = SecureStorageVault(configuration: SecureStorageVault.Configuration(accessibility: .whenUnlockedThisDeviceOnly, encryptsValues: false))
        guard case .resolve(let data) = vault.queue.sync(execute: { vault.migrateLegacyValues() }) else {
            return XCTFail("sweep did not resolve")
        }
        XCTAssertTrue(data.isEmpty)
    }
}

final class SecureStoragePluginTests: XCTestCase {
    private func invoke(_ method: (SecureStoragePlugin) -> (CAPPluginCall) -> Void, options: [String: Any] = [:]) -> (resolved: PluginCallResultData?, rejected: String?) {
        let plugin = SecureStoragePlugin()
        var resolved: PluginCallResultData?
        var rejected: String?
        let call = CAPPluginCall(callbackId: "test", methodName: "test", options: options, success: { result, _ in
            resolved = result?.data ?? [:]
        }, error: { error in
            rejected = error?.message
        })
        method(plugin)(call!)
        return (resolved, rejected)
    }

    func testStorageCallsRejectWithoutConfiguredVault() {
        let calls: [(String, (SecureStoragePlugin) -> (CAPPluginCall) -> Void, [String: Any])] = [
            ("set", SecureStoragePlugin.set, ["key": "k", "value": "v"]),
            ("set with accessibility", SecureStoragePlugin.set, ["key": "k", "value": "v", "accessibility": "always"]),
            ("get", SecureStoragePlugin.get, ["key": "k"]),
            ("keys", SecureStoragePlugin.keys, [:]),
            ("remove", SecureStoragePlugin.remove, ["key": "k"]),
            ("clear", SecureStoragePlugin.clear, [:]),
        ]
        for (name, method, options) in calls {
            let result = invoke(method, options: options)
            XCTAssertNil(result.resolved, name)
            XCTAssertEqual(result.rejected, SecureStorageVault.unsupportedConfigurationMessage, name)
        }
    }

    func testGetPlatformResolvesIos() {
        let result = invoke(SecureStoragePlugin.getPlatform)
        XCTAssertNil(result.rejected)
        XCTAssertEqual(result.resolved?["value"] as? String, "ios")
    }
}
