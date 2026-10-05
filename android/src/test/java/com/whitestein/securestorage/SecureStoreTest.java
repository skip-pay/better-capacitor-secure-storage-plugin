package com.whitestein.securestorage;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.junit.Before;
import org.junit.Test;

public class SecureStoreTest {

    private Fakes.MapStore store;
    private Fakes.FakeBackend backend;
    private Fakes.ManualExecutor sweepExecutor;
    private Fakes.RecordingSleeper sleeper;
    private SecureStore secureStore;

    @Before
    public void setUp() {
        store = new Fakes.MapStore();
        backend = new Fakes.FakeBackend();
        sweepExecutor = new Fakes.ManualExecutor();
        sleeper = new Fakes.RecordingSleeper();
        secureStore = new SecureStore(store, backend, Fakes.BASE64, sweepExecutor, sleeper, SecureStore.Logger.NONE);
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private String getString(String key) {
        SecureStore.ReadResult result = secureStore.get(key);
        assertEquals(SecureStore.Status.FOUND, result.status);
        return new String(result.value, StandardCharsets.UTF_8);
    }

    private static String repeat(String part, int times) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < times; i++) {
            builder.append(part);
        }
        return builder.toString();
    }

    // Format

    @Test
    public void setWritesV2FormatWithIvCiphertextAndTag() throws Exception {
        secureStore.set("pin", utf8("1234"));

        String raw = store.map.get("pin");
        assertTrue(raw.startsWith("v2:"));
        byte[] blob = Base64.getDecoder().decode(raw.substring(3));
        assertEquals(12 + 4 + 16, blob.length);
        assertFalse(raw.contains("1234"));
        assertEquals("1234", getString("pin"));
    }

    @Test
    public void setUsesFreshIvEachTime() throws Exception {
        secureStore.set("a", utf8("same"));
        String first = store.map.get("a");
        secureStore.set("a", utf8("same"));
        assertFalse(first.equals(store.map.get("a")));
    }

    @Test
    public void roundTripsEmptyLargeAndUnicodeValues() throws Exception {
        String large = repeat("0123456789", 2000);
        secureStore.set("empty", utf8(""));
        secureStore.set("large", utf8(large));
        secureStore.set("unicode", utf8("Příliš žluťoučký kůň 🐎"));

        assertEquals("", getString("empty"));
        assertEquals(large, getString("large"));
        assertEquals("Příliš žluťoučký kůň 🐎", getString("unicode"));
    }

    @Test
    public void legacyBase64NeverLooksLikeV2() {
        assertFalse(Fakes.androidDefaultBase64(new byte[300]).contains(":"));
        assertTrue(SecureStore.V2_PREFIX.equals("v2:"));
    }

    @Test
    public void missingKeyIsNotFoundAndCountsNothing() {
        assertEquals(SecureStore.Status.NOT_FOUND, secureStore.get("nope").status);
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(0, diagnostics.lostItems);
        assertEquals(0, diagnostics.decryptFailures);
    }

    // AAD binding and lost items

    @Test
    public void blobCopiedToAnotherKeyIsUnreadable() throws Exception {
        secureStore.set("a", utf8("secret"));
        store.map.put("b", store.map.get("a"));

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("b").status);
        assertEquals("secret", getString("a"));
        assertEquals(1, secureStore.diagnostics().lostItems);
    }

    @Test
    public void tamperedBlobIsLostKeptAndOverwritable() throws Exception {
        secureStore.set("pin", utf8("1234"));
        byte[] blob = Base64.getDecoder().decode(store.map.get("pin").substring(3));
        blob[blob.length - 1] ^= 1;
        String tampered = "v2:" + Base64.getEncoder().encodeToString(blob);
        store.map.put("pin", tampered);

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals("entry is not deleted", tampered, store.map.get("pin"));
        assertTrue("key is not deleted", backend.hasAesKey());
        assertTrue("bad tag is not retried", sleeper.sleeps.isEmpty());
        assertEquals("distinct keys", 1, secureStore.diagnostics().lostItems);

        secureStore.set("pin", utf8("5678"));
        assertEquals("5678", getString("pin"));
        assertEquals(1, backend.aesKeysCreated);
    }

    @Test
    public void v2BlobWithoutAesKeyIsLostAndNoKeyIsCreatedOnRead() throws Exception {
        secureStore.set("pin", utf8("1234"));
        backend.aesKey = null;

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertNull("a read never creates a key", backend.aesKey);
        assertEquals(1, secureStore.diagnostics().lostItems);
    }

    @Test
    public void malformedV2IsUndecodable() {
        store.map.put("bad64", "v2:@@@");
        store.map.put("short", "v2:" + Base64.getEncoder().encodeToString(new byte[27]));

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("bad64").status);
        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("short").status);
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(2, diagnostics.decryptFailures);
        assertEquals(0, diagnostics.lostItems);
    }

    // Legacy readers and lazy migration

    @Test
    public void legacyRsaSingleBlockIsReadAndMigrated() throws Exception {
        backend.createRsaKey();
        store.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));

        assertEquals("1234", getString("pin"));
        assertTrue(store.map.get("pin").startsWith("v2:"));
        assertEquals("1234", getString("pin"));
        assertEquals(1, secureStore.diagnostics().migrated);
    }

    @Test
    public void legacyRsaMultiBlockIsReadAndMigrated() throws Exception {
        backend.createRsaKey();
        String value = repeat("token-", 120);
        store.map.put("token", backend.upstreamRsaEncrypt(utf8(value)));

        assertEquals(value, getString("token"));
        assertTrue(store.map.get("token").startsWith("v2:"));
        assertEquals(value, getString("token"));
    }

    @Test
    public void legacyRsaEmptyValueIsRead() throws Exception {
        backend.createRsaKey();
        store.map.put("empty", backend.upstreamRsaEncrypt(new byte[0]));

        assertEquals("", getString("empty"));
    }

    @Test
    public void legacyRsaWithoutRsaKeyIsUndecodableAndKept() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("1234"));
        backend.rsaKey = null;
        store.map.put("pin", legacy);

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(legacy, store.map.get("pin"));
        assertEquals(1, secureStore.diagnostics().decryptFailures);
    }

    @Test
    public void legacyRsaWithReplacedRsaKeyIsLost() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("1234"));
        backend.createRsaKey();
        store.map.put("pin", legacy);

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(legacy, store.map.get("pin"));
        assertEquals(1, secureStore.diagnostics().lostItems);
    }

    @Test
    public void legacyPlaintextIsReadAndMigrated() throws Exception {
        store.map.put("pin", Fakes.androidDefaultBase64(utf8("1234")));

        assertEquals("1234", getString("pin"));
        assertTrue(store.map.get("pin").startsWith("v2:"));
        assertFalse(store.map.get("pin").contains(Base64.getEncoder().encodeToString(utf8("1234"))));
        assertEquals("1234", getString("pin"));
        assertEquals(1, secureStore.diagnostics().migrated);
    }

    @Test
    public void legacyPlaintextEmptyValueIsRead() {
        store.map.put("empty", "");
        assertEquals("", getString("empty"));
    }

    @Test
    public void legacyPlaintextOf256BytesIsReadWhenRsaKeyExists() throws Exception {
        backend.createRsaKey();
        String value = repeat("a", 256);
        store.map.put("long", Fakes.androidDefaultBase64(utf8(value)));

        assertEquals(value, getString("long"));
    }

    @Test
    public void legacyNonUtf8IsUndecodable() {
        store.map.put("bin", Fakes.androidDefaultBase64(new byte[] { (byte) 0xff, (byte) 0xfe, 0x00 }));
        store.map.put("notBase64", "%%%");

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("bin").status);
        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("notBase64").status);
        assertEquals(2, secureStore.diagnostics().decryptFailures);
    }

    @Test
    public void legacyReadSucceedsWhenAesKeyCannotBeCreated() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("1234"));
        store.map.put("pin", legacy);
        store.map.put("plain", Fakes.androidDefaultBase64(utf8("abc")));
        backend.aesCreatable = false;

        assertEquals("1234", getString("pin"));
        assertEquals("abc", getString("plain"));
        assertEquals("legacy entry kept", legacy, store.map.get("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);

        backend.aesCreatable = true;
        assertEquals("1234", getString("pin"));
        assertTrue("migrated once the keystore works", store.map.get("pin").startsWith("v2:"));
    }

    @Test
    public void legacyReadSucceedsWhenWriteBackFails() throws Exception {
        String legacy = Fakes.androidDefaultBase64(utf8("1234"));
        store.map.put("pin", legacy);
        store.failWrites = true;

        assertEquals("1234", getString("pin"));
        assertEquals(legacy, store.map.get("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
    }

    // Fail-closed writes

    @Test
    public void setFailsClosedWhenAesKeyCannotBeCreated() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("old"));
        store.map.put("pin", legacy);
        backend.aesCreatable = false;

        try {
            secureStore.set("pin", utf8("new"));
            fail("set must throw");
        } catch (StorageException expected) {}
        try {
            secureStore.set("other", utf8("new"));
            fail("set must throw");
        } catch (StorageException expected) {}

        assertEquals("previous value untouched", legacy, store.map.get("pin"));
        assertFalse("nothing stored in plaintext or RSA", store.map.containsKey("other"));
    }

    @Test
    public void setFailsWhenCommitFails() {
        store.failWrites = true;
        try {
            secureStore.set("pin", utf8("1234"));
            fail("set must throw");
        } catch (StorageException expected) {}
    }

    // Retries, no latching

    @Test
    public void transientFailuresAreRetried() throws Exception {
        secureStore.set("pin", utf8("1234"));
        backend.transientFailures = 2;

        assertEquals("1234", getString("pin"));
        assertEquals(Arrays.asList(50L, 200L), sleeper.sleeps);
    }

    @Test
    public void transientWriteFailuresAreRetried() throws Exception {
        backend.transientFailures = 2;
        secureStore.set("pin", utf8("1234"));
        assertEquals("1234", getString("pin"));
    }

    @Test
    public void exhaustedRetriesFailThisCallOnlyAndNothingIsLatched() throws Exception {
        secureStore.set("pin", utf8("1234"));
        backend.transientFailures = 3;
        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(1, secureStore.diagnostics().decryptFailures);
        assertEquals("1234", getString("pin"));

        backend.transientFailures = 3;
        try {
            secureStore.set("pin", utf8("5678"));
            fail("set must throw");
        } catch (StorageException expected) {}
        secureStore.set("pin", utf8("5678"));
        assertEquals("5678", getString("pin"));
    }

    // Sweep

    @Test
    public void sweepMigratesAllLegacyEntriesOnceInTheBackground() throws Exception {
        backend.createRsaKey();
        store.map.put("rsa", backend.upstreamRsaEncrypt(utf8("one")));
        store.map.put("plain", Fakes.androidDefaultBase64(utf8("two")));
        store.map.put("garbage", "%%%");
        secureStore.set("v2", utf8("three"));
        String v2 = store.map.get("v2");

        assertEquals("sweep is queued, not run inline", 1, sweepExecutor.tasks.size());
        assertFalse(store.map.get("rsa").startsWith("v2:"));
        sweepExecutor.runAll();

        assertTrue(store.map.get("rsa").startsWith("v2:"));
        assertTrue(store.map.get("plain").startsWith("v2:"));
        assertEquals("v2 entries untouched", v2, store.map.get("v2"));
        assertEquals("garbage kept", "%%%", store.map.get("garbage"));
        assertEquals(2, secureStore.diagnostics().migrated);
        assertEquals("one", getString("rsa"));
        assertEquals("two", getString("plain"));

        secureStore.get("rsa");
        assertTrue("sweep starts only once", sweepExecutor.tasks.isEmpty());
    }

    @Test
    public void sweepDoesNotOverwriteNewerValue() throws Exception {
        store.map.put("pin", Fakes.androidDefaultBase64(utf8("old")));
        secureStore.set("pin", utf8("new"));
        sweepExecutor.runAll();

        assertEquals("new", getString("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
    }

    // Other operations

    @Test
    public void clearKeepsKeysAndKeysListsUnreadableEntries() throws Exception {
        secureStore.set("a", utf8("1"));
        store.map.put("lost", "v2:" + Base64.getEncoder().encodeToString(new byte[40]));

        String[] keys = secureStore.keys();
        Arrays.sort(keys);
        assertArrayEquals(new String[] { "a", "lost" }, keys);
        assertTrue(secureStore.contains("lost"));

        assertTrue(secureStore.clear());
        assertEquals(0, secureStore.keys().length);
        assertTrue(backend.hasAesKey());
    }

    @Test
    public void removeDeletesUnreadableEntries() {
        store.map.put("lost", "v2:" + Base64.getEncoder().encodeToString(new byte[40]));
        assertTrue(secureStore.remove("lost"));
        assertFalse(secureStore.contains("lost"));
    }

    @Test
    public void diagnosticsReportKeyBackend() throws Exception {
        assertEquals("none", secureStore.diagnostics().keyBackend);
        backend.createRsaKey();
        assertEquals("keystoreRsaLegacy", secureStore.diagnostics().keyBackend);
        secureStore.set("a", utf8("1"));
        assertEquals("keystoreAes", secureStore.diagnostics().keyBackend);
    }

    @Test
    public void aadIsPrefixPlusKey() {
        assertArrayEquals(utf8("v2:pin"), SecureStore.aad("pin"));
    }

    @Test
    public void utf8Validation() {
        assertTrue(SecureStore.isValidUtf8(utf8("žluťoučký")));
        assertTrue(SecureStore.isValidUtf8(new byte[0]));
        assertFalse(SecureStore.isValidUtf8(new byte[] { (byte) 0xc3 }));
    }
}
