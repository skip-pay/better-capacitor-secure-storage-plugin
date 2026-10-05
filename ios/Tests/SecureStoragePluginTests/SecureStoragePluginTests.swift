import XCTest
import Capacitor
@testable import SecureStoragePlugin

// The package test bundle has no keychain entitlement (every keychain call fails with -34018), so these tests inject the
// protected-data signal, the unlock probe and the ticker and never depend on keychain results. Keychain behaviour is covered
// by the harness in ios/Tests/harness.

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

private final class Flag<Value> {
    private let lock = NSLock()
    private var storage: Value
    private var readCount = 0

    init(_ value: Value) {
        storage = value
    }

    var reads: Int {
        lock.lock()
        defer { lock.unlock() }
        return readCount
    }

    func read() -> Value {
        lock.lock()
        defer { lock.unlock() }
        readCount += 1
        return storage
    }

    func write(_ value: Value) {
        lock.lock()
        storage = value
        lock.unlock()
    }
}

/// Ticks only when the test fires it, on the vault queue, and waits for the tick to finish.
private final class ManualTicker: SecureStorageTicker {
    private let lock = NSLock()
    private var handler: (() -> Void)?
    private var queue: DispatchQueue?
    private var startCount = 0

    var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return handler != nil
    }

    var starts: Int {
        lock.lock()
        defer { lock.unlock() }
        return startCount
    }

    func start(on queue: DispatchQueue, handler: @escaping () -> Void) {
        lock.lock()
        self.queue = queue
        self.handler = handler
        startCount += 1
        lock.unlock()
    }

    func stop() {
        lock.lock()
        handler = nil
        lock.unlock()
    }

    @discardableResult
    func fire() -> Bool {
        lock.lock()
        let handler = self.handler
        let queue = self.queue
        lock.unlock()
        guard let tick = handler, let queue = queue else { return false }
        queue.sync(execute: tick)
        return true
    }

    func fire(times: Int) {
        for _ in 0..<times {
            fire()
        }
    }
}

private func describe(_ outcome: SecureStorageVault.Outcome) -> String {
    switch outcome {
    case .resolve(let data): return "resolve \(data["value"].map { "\($0)" } ?? "-")"
    case .reject(let message, let code): return "reject \(message) \(code.rawValue)"
    case .locked: return "locked"
    }
}

private func settle(_ vault: SecureStorageVault) {
    vault.drainParkedOperations()
    vault.queue.sync {}
}

private func makeVault(
    _ accessibility: SecureStorageVault.Accessibility = .whenUnlockedThisDeviceOnly,
    protectedData: @escaping () -> Bool? = { true },
    active: @escaping () -> Bool = { true },
    refresh: @escaping () -> Void = {},
    probe: @escaping () -> Bool = { true },
    ticker: SecureStorageTicker = ManualTicker()
) -> SecureStorageVault {
    return SecureStorageVault(
        configuration: SecureStorageVault.Configuration(accessibility: accessibility),
        bundleIdentifier: nil,
        isProtectedDataAvailable: protectedData,
        isApplicationActive: active,
        refreshSignals: refresh,
        unlockProbe: probe,
        ticker: ticker
    )
}

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
        XCTAssertEqual(SecureStorageVault.storageErrorMessage, "error")
        XCTAssertEqual(SecureStorageVault.removeFailedMessage, "Remove failed")
        XCTAssertEqual(SecureStorageVault.unsupportedAccessibilityMessage, "Unsupported accessibility value")
        XCTAssertEqual(SecureStorageVault.unsupportedConfigurationMessage, "Unsupported accessibility value in plugin configuration")
    }

    func testRejectCodes() {
        let codes: [(SecureStorageVault.ErrorCode, String)] = [
            (.notFound, "NOT_FOUND"),
            (.unreadable, "UNREADABLE"),
            (.locked, "LOCKED"),
            (.unsupportedAccessibility, "UNSUPPORTED_ACCESSIBILITY"),
            (.storageError, "STORAGE_ERROR"),
        ]
        for (code, rawValue) in codes {
            XCTAssertEqual(code.rawValue, rawValue)
        }
    }

    func testSecureEnclaveKeyFollowsTheConfiguredClass() {
        let expected: [(SecureStorageVault.Accessibility, CFString)] = [
            (.whenUnlocked, kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            (.whenUnlockedThisDeviceOnly, kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            (.whenPasscodeSetThisDeviceOnly, kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            (.afterFirstUnlock, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            (.afterFirstUnlockThisDeviceOnly, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
        ]
        for (accessibility, keyClass) in expected {
            XCTAssertEqual(makeVault(accessibility).keyAccessibility, keyClass, accessibility.rawValue)
        }
    }

    func testPlaintextFallbackClassIsNeverLooserThanWhenUnlockedThisDeviceOnly() {
        let strict = SecureStorageVault.plaintextFallbackAccessibility
        XCTAssertEqual(strict, .whenUnlockedThisDeviceOnly)
        XCTAssertEqual(SecureStorageVault.Accessibility.afterFirstUnlock.tightened(toAtLeast: strict), .whenUnlockedThisDeviceOnly)
        XCTAssertEqual(SecureStorageVault.Accessibility.whenPasscodeSetThisDeviceOnly.tightened(toAtLeast: strict), .whenPasscodeSetThisDeviceOnly)
    }

    func testResolveAccessibilityFallsBackToConfiguredDefault() {
        let vault = makeVault(.whenUnlockedThisDeviceOnly)
        XCTAssertEqual(vault.resolveAccessibility(nil), .whenUnlockedThisDeviceOnly)
        XCTAssertEqual(vault.resolveAccessibility("afterFirstUnlock"), .afterFirstUnlock)
        XCTAssertNil(vault.resolveAccessibility("always"))
        XCTAssertNil(vault.resolveAccessibility(""))
    }
}

final class SecureStorageAccessGroupTests: XCTestCase {
    func testAppPrivateGroupUsesTheTeamPrefixOfTheDefaultGroup() {
        XCTAssertEqual(SecureStorageVault.appPrivateGroup(defaultGroup: "ABCDE12345.group.cz.mallpay.widget", bundleIdentifier: "cz.mallpay"), "ABCDE12345.cz.mallpay")
        XCTAssertEqual(SecureStorageVault.appPrivateGroup(defaultGroup: "ABCDE12345.cz.mallpay", bundleIdentifier: "cz.mallpay"), "ABCDE12345.cz.mallpay")
        XCTAssertEqual(SecureStorageVault.appPrivateGroup(defaultGroup: "ABCDE12345.capacitor-secure-storage-plugin.harness.shared", bundleIdentifier: "capacitor-secure-storage-plugin.harness"), "ABCDE12345.capacitor-secure-storage-plugin.harness")
    }

    func testAppPrivateGroupNeedsATeamPrefixAndABundleIdentifier() {
        XCTAssertNil(SecureStorageVault.appPrivateGroup(defaultGroup: "nodot", bundleIdentifier: "cz.mallpay"))
        XCTAssertNil(SecureStorageVault.appPrivateGroup(defaultGroup: ".leading", bundleIdentifier: "cz.mallpay"))
        XCTAssertNil(SecureStorageVault.appPrivateGroup(defaultGroup: "ABCDE12345.cz.mallpay", bundleIdentifier: nil))
        XCTAssertNil(SecureStorageVault.appPrivateGroup(defaultGroup: "ABCDE12345.cz.mallpay", bundleIdentifier: ""))
    }

    func testAccessGroupModeTargetsTheExplicitGroupFirst() {
        let explicit = SecureStorageVault.AccessGroupMode(explicitGroup: "T.app", defaultGroup: "T.group.widget")
        XCTAssertEqual(explicit.targetGroup, "T.app")
        XCTAssertTrue(explicit.isExplicit)
        let fallback = SecureStorageVault.AccessGroupMode(explicitGroup: nil, defaultGroup: "T.group.widget")
        XCTAssertEqual(fallback.targetGroup, "T.group.widget")
        XCTAssertFalse(fallback.isExplicit)
        XCTAssertNil(SecureStorageVault.AccessGroupMode(explicitGroup: nil, defaultGroup: nil).targetGroup)
    }
}

final class SecureStorageGateTests: XCTestCase {
    func testParkedOperationBlocksLaterOperationsAndSettlesOnce() {
        let vault = makeVault()
        let log = EventLog()
        var attempts = 0
        vault.submitOperation(named: "first", key: "k", run: {
            attempts += 1
            return attempts < 4 ? .locked : .resolve(["value": "one"])
        }, completion: { log.record("first \(describe($0))") })
        vault.submitOperation(named: "second", key: "k", run: { .resolve(["value": "two"]) }, completion: { log.record("second \(describe($0))") })
        vault.queue.sync {}
        XCTAssertTrue(log.events.isEmpty)
        XCTAssertEqual(vault.queue.sync { attempts }, 2)
        settle(vault)
        XCTAssertTrue(log.events.isEmpty)
        XCTAssertEqual(vault.queue.sync { attempts }, 3)
        settle(vault)
        XCTAssertEqual(log.events, ["first resolve one", "second resolve two"])
        vault.submitOperation(named: "third", key: "k", run: { .locked }, completion: { log.record("third \(describe($0))") })
        settle(vault)
        settle(vault)
        XCTAssertEqual(log.events, ["first resolve one", "second resolve two"])
    }

    func testDrainStopsAtFirstReparkedOperation() {
        let vault = makeVault()
        let log = EventLog()
        var runs: [String] = []
        var headReady = false
        var middleReady = false
        vault.submitOperation(named: "X", key: "x", run: { runs.append("X"); return headReady ? .resolve(["value": "x"]) : .locked }, completion: { log.record("X \(describe($0))") })
        vault.submitOperation(named: "Y", key: "y", run: { runs.append("Y"); return middleReady ? .resolve(["value": "y"]) : .locked }, completion: { log.record("Y \(describe($0))") })
        vault.submitOperation(named: "Z", key: "z", run: { runs.append("Z"); return .resolve(["value": "z"]) }, completion: { log.record("Z \(describe($0))") })
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
            let available = Flag<Bool?>(false)
            let vault = makeVault(accessibility, protectedData: { available.read() })
            let log = EventLog()
            vault.submitOperation(named: "A", key: "a", run: { log.record("run A"); return .resolve(["value": "a"]) }, completion: { log.record("A \(describe($0))") })
            vault.submitOperation(named: "B", key: "b", run: { log.record("run B"); return .resolve(["value": "b"]) }, completion: { log.record("B \(describe($0))") })
            vault.queue.sync {}
            XCTAssertTrue(log.events.isEmpty, accessibility.rawValue)
            XCTAssertGreaterThan(available.reads, 0, accessibility.rawValue)
            available.write(true)
            settle(vault)
            XCTAssertEqual(log.events, ["run A", "A resolve a", "run B", "B resolve b"], accessibility.rawValue)
        }
    }

    func testUnknownProtectedDataCountsAsAvailableForTheGate() {
        let vault = makeVault(.whenUnlockedThisDeviceOnly, protectedData: { nil })
        let log = EventLog()
        vault.submitOperation(named: "A", key: "a", run: { log.record("run A"); return .resolve(["value": "a"]) }, completion: { log.record("A \(describe($0))") })
        vault.queue.sync {}
        XCTAssertEqual(log.events, ["run A", "A resolve a"])
    }

    func testGateIsBypassedWhenDefaultClassIsAvailableAfterFirstUnlock() {
        for accessibility in [SecureStorageVault.Accessibility.afterFirstUnlock, .afterFirstUnlockThisDeviceOnly] {
            let available = Flag<Bool?>(false)
            let vault = makeVault(accessibility, protectedData: { available.read() })
            let log = EventLog()
            vault.submitOperation(named: "A", key: "a", run: { .resolve(["value": "a"]) }, completion: { log.record("A \(describe($0))") })
            vault.submitOperation(named: "B", key: "b", run: { .reject("nope", code: .storageError) }, completion: { log.record("B \(describe($0))") })
            vault.queue.sync {}
            XCTAssertEqual(log.events, ["A resolve a", "B reject nope STORAGE_ERROR"], accessibility.rawValue)
            XCTAssertEqual(available.reads, 0, accessibility.rawValue)
        }
    }

    func testLockedOutcomeStillParksWhenGateIsBypassed() {
        let vault = makeVault(.afterFirstUnlock, protectedData: { false })
        let log = EventLog()
        var locked = true
        vault.submitOperation(named: "A", key: "a", run: { locked ? .locked : .resolve(["value": "a"]) }, completion: { log.record("A \(describe($0))") })
        vault.submitOperation(named: "B", key: "b", run: { .resolve(["value": "b"]) }, completion: { log.record("B \(describe($0))") })
        vault.queue.sync {}
        XCTAssertTrue(log.events.isEmpty)
        vault.queue.sync { locked = false }
        settle(vault)
        XCTAssertEqual(log.events, ["A resolve a", "B resolve b"])
    }

    func testParkedCounterCountsEachCallOnce() {
        let vault = makeVault()
        var locked = true
        vault.submitOperation(named: "A", key: "a", run: { locked ? .locked : .resolve([:]) })
        vault.submitOperation(named: "B", key: "b", run: { locked ? .locked : .resolve([:]) })
        for _ in 0..<5 {
            settle(vault)
        }
        XCTAssertEqual(vault.queue.sync { vault.counters.parked }, 1, "B never ran while A was parked")
        vault.queue.sync { locked = false }
        settle(vault)
        vault.submitOperation(named: "C", key: "c", run: { .resolve([:]) })
        vault.queue.sync {}
        XCTAssertEqual(vault.queue.sync { vault.counters.parked }, 1)
    }
}

final class SecureStorageTimerTests: XCTestCase {
    func testTickerRunsOnlyWhileSomethingIsParked() {
        let ticker = ManualTicker()
        let vault = makeVault(ticker: ticker)
        let log = EventLog()
        var locked = true
        vault.submitOperation(named: "A", key: "a", run: { locked ? .locked : .resolve(["value": "a"]) }, completion: { log.record("A \(describe($0))") })
        vault.queue.sync {}
        XCTAssertTrue(ticker.isRunning)
        XCTAssertTrue(vault.queue.sync { vault.isTickerRunning })
        settle(vault)
        XCTAssertEqual(ticker.starts, 1, "a running ticker is not started twice")
        vault.queue.sync { locked = false }
        ticker.fire()
        XCTAssertEqual(log.events, ["A resolve a"])
        XCTAssertFalse(ticker.isRunning)
        XCTAssertFalse(vault.queue.sync { vault.isTickerRunning })
        vault.submitOperation(named: "B", key: "b", run: { .resolve([:]) })
        vault.queue.sync {}
        XCTAssertEqual(ticker.starts, 1, "nothing parked, no ticker")
    }

    func testTickRecoversFromAMissedUnlockNotification() {
        let ticker = ManualTicker()
        let device = Flag(false)
        let signal = Flag<Bool?>(false)
        let refreshes = Flag(0)
        let vault = makeVault(.whenUnlockedThisDeviceOnly, protectedData: { signal.read() }, refresh: {
            refreshes.write(refreshes.read() + 1)
            signal.write(device.read())
        }, ticker: ticker)
        let log = EventLog()
        vault.submitOperation(named: "get", key: "k", run: { log.record("run"); return .resolve(["value": "v"]) }, completion: { log.record("get \(describe($0))") })
        vault.queue.sync {}
        ticker.fire()
        XCTAssertTrue(log.events.isEmpty, "still locked")
        device.write(true)
        ticker.fire()
        XCTAssertEqual(log.events, ["run", "get resolve v"], "the tick re-read the state and drained without a notification")
        XCTAssertEqual(refreshes.read(), 2)
        XCTAssertFalse(ticker.isRunning)
    }

    func testTickDoesNotAskForARefreshWhileProtectedDataIsKnownAvailable() {
        let ticker = ManualTicker()
        let refreshes = Flag(0)
        let vault = makeVault(.afterFirstUnlock, protectedData: { true }, refresh: { refreshes.write(refreshes.read() + 1) }, probe: { false }, ticker: ticker)
        vault.submitOperation(named: "A", key: "a", run: { .locked })
        vault.queue.sync {}
        ticker.fire(times: 3)
        XCTAssertEqual(refreshes.read(), 0)
    }

    func testParkedCallHasNoAbsoluteTimeout() {
        let ticker = ManualTicker()
        let vault = makeVault(.whenUnlockedThisDeviceOnly, protectedData: { false }, ticker: ticker)
        let log = EventLog()
        vault.submitOperation(named: "get", key: "k", run: { .resolve(["value": "v"]) }, completion: { log.record("get \(describe($0))") })
        vault.queue.sync {}
        ticker.fire(times: 500)
        XCTAssertTrue(log.events.isEmpty)
        XCTAssertEqual(vault.queue.sync { vault.parkedCount }, 1)
        XCTAssertTrue(ticker.isRunning)
    }

    func testDispatchTickerFiresOnTheVaultQueueAndStops() {
        let ticker = SecureStorageDispatchTicker(interval: .milliseconds(20))
        let vault = makeVault(ticker: ticker)
        let fired = expectation(description: "a parked call is retried by the real timer")
        var attempts = 0
        vault.submitOperation(named: "A", key: "a", run: {
            attempts += 1
            return attempts < 3 ? .locked : .resolve([:])
        }, completion: { _ in fired.fulfill() })
        wait(for: [fired], timeout: 5)
        XCTAssertFalse(vault.queue.sync { vault.isTickerRunning })
    }
}

final class SecureStorageEscapeTests: XCTestCase {
    func testLockedWhileUnlockedBecomesLostAfterThreeTickRetries() {
        let ticker = ManualTicker()
        let probes = Flag(0)
        let vault = makeVault(probe: { probes.write(probes.read() + 1); return true }, ticker: ticker)
        let log = EventLog()
        var runs = 0
        vault.submitOperation(named: "get", key: "pin", run: { runs += 1; return .locked }, lost: {
            log.record("lost handler")
            return .reject(SecureStorageVault.missingItemMessage, code: .unreadable)
        }, completion: { log.record("get \(describe($0))") })
        vault.submitOperation(named: "after", key: "x", run: { .resolve(["value": "x"]) }, completion: { log.record("after \(describe($0))") })
        vault.queue.sync {}
        for _ in 0..<5 {
            settle(vault)
        }
        XCTAssertTrue(log.events.isEmpty, "drains between ticks do not use up retries")
        XCTAssertEqual(probes.read(), 1)
        ticker.fire(times: 2)
        XCTAssertTrue(log.events.isEmpty, "first result plus two retries")
        XCTAssertEqual(vault.queue.sync { vault.counters.lostItems }, 0)
        ticker.fire()
        XCTAssertEqual(log.events, ["lost handler", "get reject Item with given key does not exist UNREADABLE", "after resolve x"])
        XCTAssertEqual(vault.queue.sync { runs }, 2 + 5 + 3, "one run per submit, drain and tick")
        XCTAssertEqual(vault.queue.sync { vault.counters.lostItems }, 1)
        XCTAssertEqual(vault.queue.sync { vault.counters.parked }, 1)
        XCTAssertFalse(ticker.isRunning)
    }

    func testUnknownProtectedDataNeverClassifiesAsLost() {
        let ticker = ManualTicker()
        let vault = makeVault(.afterFirstUnlock, protectedData: { nil }, ticker: ticker)
        let log = EventLog()
        vault.submitOperation(named: "get", key: "pin", run: { .locked }, completion: { log.record("get \(describe($0))") })
        vault.queue.sync {}
        ticker.fire(times: 20)
        XCTAssertTrue(log.events.isEmpty)
        XCTAssertEqual(vault.queue.sync { vault.counters.lostItems }, 0)
    }

    func testUnavailableProtectedDataNeverClassifiesAsLost() {
        let ticker = ManualTicker()
        let vault = makeVault(.afterFirstUnlock, protectedData: { false }, ticker: ticker)
        let log = EventLog()
        vault.submitOperation(named: "get", key: "pin", run: { .locked }, completion: { log.record("get \(describe($0))") })
        vault.queue.sync {}
        ticker.fire(times: 20)
        XCTAssertTrue(log.events.isEmpty)
    }

    func testAStaleSignalIsCaughtByTheUnlockProbe() {
        let ticker = ManualTicker()
        let keychainUnlocked = Flag(false)
        let vault = makeVault(protectedData: { true }, probe: { keychainUnlocked.read() }, ticker: ticker)
        let log = EventLog()
        var locked = true
        vault.submitOperation(named: "get", key: "pin", run: { locked ? .locked : .resolve(["value": "1234"]) }, completion: { log.record("get \(describe($0))") })
        vault.queue.sync {}
        ticker.fire(times: 20)
        XCTAssertTrue(log.events.isEmpty, "signal says unlocked, keychain says locked: keep waiting")
        vault.queue.sync { locked = false }
        ticker.fire()
        XCTAssertEqual(log.events, ["get resolve 1234"], "the real value once the device unlocks")
    }

    func testRetriesOnlyCountWhileTheProbeConfirmsAnUnlockedKeychain() {
        let ticker = ManualTicker()
        let keychainUnlocked = Flag(false)
        let vault = makeVault(probe: { keychainUnlocked.read() }, ticker: ticker)
        let log = EventLog()
        vault.submitOperation(named: "get", key: "pin", run: { .locked }, completion: { log.record("get \(describe($0))") })
        vault.queue.sync {}
        ticker.fire(times: 10)
        keychainUnlocked.write(true)
        ticker.fire(times: 3)
        XCTAssertTrue(log.events.isEmpty)
        ticker.fire()
        XCTAssertEqual(log.events, ["get reject Item with given key does not exist UNREADABLE"])
    }

    func testLostHandlerThatIsStillLockedRejectsWithStorageError() {
        let ticker = ManualTicker()
        let vault = makeVault(ticker: ticker)
        let log = EventLog()
        vault.submitOperation(named: "set", key: "pin", run: { .locked }, lost: { .locked }, completion: { log.record("set \(describe($0))") })
        vault.queue.sync {}
        ticker.fire(times: 3)
        XCTAssertEqual(log.events, ["set reject error STORAGE_ERROR"])
        XCTAssertFalse(ticker.isRunning)
    }

    func testGatedCallsNeverCountTowardsLost() {
        let ticker = ManualTicker()
        let vault = makeVault(.whenUnlockedThisDeviceOnly, protectedData: { false }, ticker: ticker)
        var runs = 0
        vault.submitOperation(named: "get", key: "pin", run: { runs += 1; return .resolve([:]) })
        vault.queue.sync {}
        ticker.fire(times: 10)
        XCTAssertEqual(vault.queue.sync { runs }, 0)
        XCTAssertEqual(vault.queue.sync { vault.counters.lostItems }, 0)
    }
}

final class SecureStorageSweepTests: XCTestCase {
    func testSweepSkipsLockedKeysAndContinues() {
        let vault = makeVault()
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

    func testSweepReportsSkippedKeys() {
        let vault = makeVault()
        guard case .resolve(let data) = vault.migrateKeys(["a", "b", "c", "d"], using: { $0 == "a" || $0 == "c" ? .locked : .resolve([:]) }) else {
            return XCTFail("sweep did not resolve")
        }
        XCTAssertEqual(data["skipped"] as? Int, 2)
    }

    func testSweepNeverRunsWhileProtectedDataIsUnavailable() {
        let vault = makeVault(protectedData: { false })
        guard case .resolve(let data) = vault.queue.sync(execute: { vault.migrateLegacyValues() }) else {
            return XCTFail("sweep did not resolve")
        }
        XCTAssertEqual(data["skipped"] as? Int, 1)
    }

    func testSweepWaitsForForegroundAndProtectedDataAndRunsBehindQueuedCalls() {
        let available = Flag<Bool?>(false)
        let active = Flag(false)
        let vault = makeVault(protectedData: { available.read() }, active: { active.read() })
        let log = EventLog()
        vault.requestSweep { _ in log.record("sweep"); return true }
        vault.submitOperation(named: "get", key: "k", run: { log.record("run get"); return .resolve(["value": "v"]) }, completion: { log.record("get \(describe($0))") })
        settle(vault)
        XCTAssertTrue(log.events.isEmpty)
        available.write(nil)
        active.write(true)
        settle(vault)
        XCTAssertEqual(log.events, ["run get", "get resolve v"], "unknown protected data is not enough for the sweep")
        available.write(true)
        active.write(false)
        settle(vault)
        XCTAssertEqual(log.events, ["run get", "get resolve v"], "sweep waits for the foreground")
        active.write(true)
        settle(vault)
        XCTAssertEqual(log.events, ["run get", "get resolve v", "sweep"])
        settle(vault)
        XCTAssertEqual(log.events.filter { $0 == "sweep" }.count, 1, "once per process")
        vault.requestSweep()
        settle(vault)
        XCTAssertEqual(log.events.filter { $0 == "sweep" }.count, 2, "an explicit request runs the sweep again")
    }

    func testSweepWaitsForParkedCalls() {
        let vault = makeVault()
        let log = EventLog()
        var locked = true
        vault.submitOperation(named: "get", key: "k", run: { locked ? .locked : .resolve(["value": "v"]) }, completion: { log.record("get \(describe($0))") })
        vault.requestSweep { _ in log.record("sweep"); return true }
        settle(vault)
        XCTAssertTrue(log.events.isEmpty)
        vault.queue.sync { locked = false }
        settle(vault)
        XCTAssertEqual(log.events, ["get resolve v", "sweep"])
    }

    func testIncompleteSweepRunsAgainOnLaterDrainsUpToTheLimit() {
        let vault = makeVault()
        let log = EventLog()
        vault.requestSweep { _ in log.record("sweep"); return false }
        for _ in 0..<6 {
            settle(vault)
        }
        XCTAssertEqual(log.events.count, SecureStorageVault.sweepAttempts)
    }
}

final class SecureStoragePluginTests: XCTestCase {
    private func invoke(_ method: (SecureStoragePlugin) -> (CAPPluginCall) -> Void, options: [String: Any] = [:]) -> (resolved: PluginCallResultData?, rejected: String?, code: String?) {
        let plugin = SecureStoragePlugin()
        var resolved: PluginCallResultData?
        var rejected: String?
        var code: String?
        let call = CAPPluginCall(callbackId: "test", methodName: "test", options: options, success: { result, _ in
            resolved = result?.data ?? [:]
        }, error: { error in
            rejected = error?.message
            code = error?.code
        })
        method(plugin)(call!)
        return (resolved, rejected, code)
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
            XCTAssertEqual(result.code, "UNSUPPORTED_ACCESSIBILITY", name)
        }
    }

    func testGetPlatformResolvesIos() {
        let result = invoke(SecureStoragePlugin.getPlatform)
        XCTAssertNil(result.rejected)
        XCTAssertEqual(result.resolved?["value"] as? String, "ios")
    }

    func testGetDiagnosticsResolvesWithoutConfiguredVault() {
        let result = invoke(SecureStoragePlugin.getDiagnostics)
        XCTAssertNil(result.rejected)
        for counter in ["parked", "migrated", "duplicatesResolved", "lostItems", "decryptFailures", "plaintextFallbacks"] {
            XCTAssertEqual(result.resolved?[counter] as? Int, 0, counter)
        }
        XCTAssertEqual(result.resolved?["keyBackend"] as? String, "none")
        XCTAssertEqual(result.resolved?["accessGroupMode"] as? String, "default")
        XCTAssertEqual(result.resolved?.count, 8)
    }

    func testPluginMethodsAreAdditive() {
        let names = SecureStoragePlugin().pluginMethods.map { $0.name }
        XCTAssertEqual(names, ["set", "get", "keys", "remove", "clear", "getPlatform", "getDiagnostics"])
        XCTAssertEqual(SecureStoragePlugin().jsName, "SecureStoragePlugin")
    }
}
