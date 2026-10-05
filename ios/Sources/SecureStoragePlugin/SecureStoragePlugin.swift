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
    ]
    private var vault: SecureStorageVault?

    override public func load() {
        guard let configuration = readConfiguration() else { return }
        let vault = SecureStorageVault(configuration: configuration, isProtectedDataAvailable: {
            DispatchQueue.main.sync { UIApplication.shared.isProtectedDataAvailable }
        })
        self.vault = vault
        observeWakeEvents()
        vault.submitOperation(named: "sweep", key: "*", run: { vault.migrateLegacyValues() })
    }

    @objc func set(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        let key = call.getString("key") ?? ""
        let value = call.getString("value") ?? ""
        guard let accessibility = vault.resolveAccessibility(call.getString("accessibility")) else {
            call.reject(SecureStorageVault.unsupportedAccessibilityMessage)
            return
        }
        submitCall(call, to: vault, named: "set", key: key) { vault in vault.storeValue(value, forKey: key, accessibility: accessibility) }
    }

    @objc func get(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        let key = call.getString("key") ?? ""
        submitCall(call, to: vault, named: "get", key: key) { vault in vault.loadValue(forKey: key) }
    }

    @objc func keys(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        submitCall(call, to: vault, named: "keys", key: "*") { vault in vault.listStoredKeys() }
    }

    @objc func remove(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        let key = call.getString("key") ?? ""
        submitCall(call, to: vault, named: "remove", key: key) { vault in vault.removeValue(forKey: key) }
    }

    @objc func clear(_ call: CAPPluginCall) {
        guard let vault = requireVault(for: call) else { return }
        submitCall(call, to: vault, named: "clear", key: "*") { vault in vault.removeAllValues() }
    }

    @objc func getPlatform(_ call: CAPPluginCall) {
        call.resolve([
            "value": "ios"
        ])
    }

    private func readConfiguration() -> SecureStorageVault.Configuration? {
        let config = getConfig()
        return SecureStorageVault.Configuration(
            requestedAccessibility: config.getString("accessibility"),
            encryptsValues: config.getBoolean("encryptValues", false)
        )
    }

    private func requireVault(for call: CAPPluginCall) -> SecureStorageVault? {
        guard let vault = vault else {
            call.reject(SecureStorageVault.unsupportedConfigurationMessage)
            return nil
        }
        return vault
    }

    private func submitCall(_ call: CAPPluginCall, to vault: SecureStorageVault, named name: String, key: String, run: @escaping (SecureStorageVault) -> SecureStorageVault.Outcome) {
        vault.submitOperation(named: name, key: key, run: { run(vault) }, completion: { outcome in
            switch outcome {
            case .resolve(let data):
                call.resolve(data)
            case .reject(let message):
                call.reject(message)
            case .locked:
                break
            }
        })
    }

    private func observeWakeEvents() {
        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(resumeParkedOperations), name: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil)
        center.addObserver(self, selector: #selector(resumeParkedOperations), name: UIApplication.willEnterForegroundNotification, object: nil)
        center.addObserver(self, selector: #selector(resumeParkedOperations), name: UIApplication.didBecomeActiveNotification, object: nil)
    }

    @objc private func resumeParkedOperations() {
        vault?.drainParkedOperations()
    }
}
