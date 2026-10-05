import Foundation
import UIKit
import Capacitor

@objc(SecureStoragePlugin)
public class SecureStoragePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "SecureStoragePlugin"
    public let jsName = "SecureStoragePlugin"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "set", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "get", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "keys", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "remove", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "clear", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getPlatform", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getDiagnostics", returnType: CAPPluginReturnPromise),
    ]
    private var vault: SecureStorageVault?
    private let signals = SecureStorageSignals()

    override public func load() {
        guard let configuration = readConfiguration() else { return }
        let signals = self.signals
        let vault = SecureStorageVault(
            configuration: configuration,
            isProtectedDataAvailable: { signals.isProtectedDataAvailable },
            isApplicationActive: { signals.isApplicationActive },
            refreshSignals: { [weak self] in self?.refreshSignals() }
        )
        self.vault = vault
        observeSignals()
        refreshSignals()
        vault.requestSweep()
    }

    @objc func set(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        let key = call.getString("key") ?? ""
        let value = call.getString("value") ?? ""
        guard let accessibility = vault.resolveAccessibility(call.getString("accessibility")) else {
            call.reject(SecureStorageVault.unsupportedAccessibilityMessage, SecureStorageVault.ErrorCode.unsupportedAccessibility.rawValue)
            return
        }
        submitCall(call, to: vault, named: "set", key: key, run: { vault in
            vault.storeValue(value, forKey: key, accessibility: accessibility)
        }, lost: { vault in
            vault.replaceLostValue(value, forKey: key, accessibility: accessibility)
        })
    }

    @objc func get(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        let key = call.getString("key") ?? ""
        submitCall(call, to: vault, named: "get", key: key, run: { vault in vault.loadValue(forKey: key) }, lost: { vault in vault.lostValue(forKey: key) })
    }

    @objc func keys(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        submitCall(call, to: vault, named: "keys", key: "*", run: { vault in vault.listStoredKeys() }, lost: { vault in vault.lostKeyList() })
    }

    @objc func remove(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        let key = call.getString("key") ?? ""
        submitCall(call, to: vault, named: "remove", key: key, run: { vault in vault.removeValue(forKey: key) }, lost: { vault in vault.removeLostValue(forKey: key) })
    }

    @objc func clear(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        submitCall(call, to: vault, named: "clear", key: "*", run: { vault in vault.removeAllValues() }, lost: { vault in vault.removeAllLostValues() })
    }

    @objc func getPlatform(_ call: CAPPluginCall) {
        call.resolve([
            "value": "ios"
        ])
    }

    /// Resolves right away, also while calls are parked: it runs on the vault queue but outside the parked FIFO.
    @objc func getDiagnostics(_ call: CAPPluginCall) {
        guard let vault = vault else {
            call.resolve(SecureStorageVault.emptyDiagnostics)
            return
        }
        vault.queue.async {
            call.resolve(vault.diagnostics())
        }
    }

    private func readConfiguration() -> SecureStorageVault.Configuration? {
        let config = getConfig()
        return SecureStorageVault.Configuration(
            requestedAccessibility: config.getString("accessibility"),
            encryptsValues: config.getBoolean("encryptValues", true)
        )
    }

    private func requireVault(for call: CAPPluginCall) -> SecureStorageVault? {
        guard let vault = vault else {
            call.reject(SecureStorageVault.unsupportedConfigurationMessage, SecureStorageVault.ErrorCode.unsupportedAccessibility.rawValue)
            return nil
        }
        return vault
    }

    private func submitCall(
        _ call: CAPPluginCall,
        to vault: SecureStorageVault,
        named name: String,
        key: String,
        run: @escaping (SecureStorageVault) -> SecureStorageVault.Outcome,
        lost: @escaping (SecureStorageVault) -> SecureStorageVault.Outcome
    ) {
        vault.submitOperation(named: name, key: key, run: { run(vault) }, lost: { lost(vault) }, completion: { outcome in
            switch outcome {
            case .resolve(let data):
                call.resolve(data)
            case .reject(let message, let code):
                call.reject(message, code.rawValue)
            case .locked:
                break
            }
        })
    }

    private func observeSignals() {
        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(protectedDataWillBecomeUnavailable), name: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil)
        center.addObserver(self, selector: #selector(protectedDataDidBecomeAvailable), name: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil)
        center.addObserver(self, selector: #selector(applicationStateChanged), name: UIApplication.willEnterForegroundNotification, object: nil)
        center.addObserver(self, selector: #selector(applicationStateChanged), name: UIApplication.didBecomeActiveNotification, object: nil)
        center.addObserver(self, selector: #selector(applicationStateChanged), name: UIApplication.didEnterBackgroundNotification, object: nil)
    }

    /// Reads the UIKit state on the main thread without blocking the caller, then retries the parked calls.
    private func refreshSignals() {
        DispatchQueue.main.async { [weak self] in
            self?.readSignals()
        }
    }

    private func readSignals() {
        let application = UIApplication.shared
        signals.setProtectedDataAvailable(application.isProtectedDataAvailable)
        signals.setApplicationActive(application.applicationState == .active)
        vault?.drainParkedOperations()
    }

    @objc private func protectedDataWillBecomeUnavailable() {
        signals.setProtectedDataAvailable(false)
    }

    @objc private func protectedDataDidBecomeAvailable() {
        signals.setProtectedDataAvailable(true)
        vault?.drainParkedOperations()
    }

    @objc private func applicationStateChanged() {
        readSignals()
    }
}
