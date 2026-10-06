package com.whitestein.securestorage;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import org.junit.Before;
import org.junit.Test;

public class SecureStoreTest {

    private Fakes.MapStore store;
    private Fakes.MapStore legacyStore;
    private Fakes.FakeBackend backend;
    private Fakes.ManualExecutor sweepExecutor;
    private Fakes.RecordingSleeper sleeper;
    private SecureStore secureStore;

    @Before
    public void setUp() {
        store = new Fakes.MapStore();
        legacyStore = new Fakes.MapStore();
        backend = new Fakes.FakeBackend();
        sweepExecutor = new Fakes.ManualExecutor();
        sleeper = new Fakes.RecordingSleeper();
        secureStore = newSecureStore(false);
    }

    private SecureStore newSecureStore(boolean deleteLegacyStorage) {
        return new SecureStore(
            store,
            legacyStore,
            deleteLegacyStorage,
            backend,
            Fakes.BASE64,
            sweepExecutor,
            sleeper,
            SecureStore.Logger.NONE
        );
    }

    private void deleteLegacyStorage() {
        secureStore = newSecureStore(true);
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
        legacyStore.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));

        assertEquals("1234", getString("pin"));
        assertTrue(store.map.get("pin").startsWith("v2:"));
        assertEquals("1234", getString("pin"));
        assertEquals(1, secureStore.diagnostics().migrated);
    }

    @Test
    public void legacyRsaMultiBlockIsReadAndMigrated() throws Exception {
        backend.createRsaKey();
        String value = repeat("token-", 120);
        legacyStore.map.put("token", backend.upstreamRsaEncrypt(utf8(value)));

        assertEquals(value, getString("token"));
        assertTrue(store.map.get("token").startsWith("v2:"));
        assertEquals(value, getString("token"));
    }

    @Test
    public void legacyRsaEmptyValueIsRead() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("empty", backend.upstreamRsaEncrypt(new byte[0]));

        assertEquals("", getString("empty"));
    }

    @Test
    public void legacyRsaWithoutRsaKeyIsUndecodableAndKept() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("1234"));
        backend.rsaKey = null;
        legacyStore.map.put("pin", legacy);

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(legacy, legacyStore.map.get("pin"));
        assertEquals(1, secureStore.diagnostics().decryptFailures);
    }

    @Test
    public void legacyRsaWithReplacedRsaKeyIsLost() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("1234"));
        backend.createRsaKey();
        legacyStore.map.put("pin", legacy);

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(legacy, legacyStore.map.get("pin"));
        assertEquals(1, secureStore.diagnostics().lostItems);
    }

    @Test
    public void legacyPlaintextIsReadAndMigrated() throws Exception {
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("1234")));

        assertEquals("1234", getString("pin"));
        assertTrue(store.map.get("pin").startsWith("v2:"));
        assertFalse(store.map.get("pin").contains(Base64.getEncoder().encodeToString(utf8("1234"))));
        assertEquals("1234", getString("pin"));
        assertEquals(1, secureStore.diagnostics().migrated);
    }

    @Test
    public void legacyPlaintextEmptyValueIsRead() {
        legacyStore.map.put("empty", "");
        assertEquals("", getString("empty"));
    }

    @Test
    public void legacyPlaintextOf256BytesIsReadWhenRsaKeyExists() throws Exception {
        backend.createRsaKey();
        String value = repeat("a", 256);
        legacyStore.map.put("long", Fakes.androidDefaultBase64(utf8(value)));

        assertEquals(value, getString("long"));
    }

    @Test
    public void legacyNonUtf8IsUndecodable() {
        legacyStore.map.put("bin", Fakes.androidDefaultBase64(new byte[] { (byte) 0xff, (byte) 0xfe, 0x00 }));
        // android.util.Base64 decodes "%%%" to zero bytes without throwing, like the fake now does,
        // so this holds on a device only because the reader rejects non-base64 text itself.
        legacyStore.map.put("notBase64", "%%%");

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("bin").status);
        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("notBase64").status);
        assertEquals("%%%", legacyStore.map.get("notBase64"));
        assertEquals(2, secureStore.diagnostics().decryptFailures);
    }

    @Test
    public void legacyWithCharactersOutsideBase64IsUndecodable() {
        // On a device "QUJD%" decodes to "ABC" and "\n" to nothing.
        legacyStore.map.put("junk", Fakes.androidDefaultBase64(utf8("ABC")).trim() + "%");
        legacyStore.map.put("blank", "\n");

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("junk").status);
        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("blank").status);
        assertEquals(2, secureStore.diagnostics().decryptFailures);
        assertEquals(0, secureStore.diagnostics().migrated);
    }

    @Test
    public void fakeBase64DecodesLikeAndroid() {
        assertArrayEquals(new byte[0], Fakes.BASE64.decode("%%%"));
        assertArrayEquals(utf8("ABC"), Fakes.BASE64.decode("QU%J\nD"));
        assertArrayEquals(utf8("A"), Fakes.BASE64.decode("QQ=="));
        assertArrayEquals(utf8("A"), Fakes.BASE64.decode("QQ"));
        assertArrayEquals(utf8("AB"), Fakes.BASE64.decode("QUI="));
        for (String bad : new String[] { "Q", "QQ=", "=QQQ", "QQ==Q", "QUI=Q" }) {
            try {
                Fakes.BASE64.decode(bad);
                fail("must throw for " + bad);
            } catch (IllegalArgumentException expected) {}
        }
    }

    @Test
    public void base64TextCheck() {
        assertTrue(SecureStore.isBase64Text(""));
        assertTrue(SecureStore.isBase64Text("QUJD\nQUI=\r\n"));
        assertFalse(SecureStore.isBase64Text("QUJD%"));
        assertFalse(SecureStore.isBase64Text("v2:QUJD"));
        assertFalse(SecureStore.isBase64Text("QUJD\u00e9"));
    }

    @Test
    public void legacyReadSucceedsWhenAesKeyCannotBeCreated() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("1234"));
        legacyStore.map.put("pin", legacy);
        legacyStore.map.put("plain", Fakes.androidDefaultBase64(utf8("abc")));
        backend.aesCreatable = false;

        assertEquals("1234", getString("pin"));
        assertEquals("abc", getString("plain"));
        assertEquals("legacy entry kept", legacy, legacyStore.map.get("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
        assertEquals(2, secureStore.diagnostics().migrationSkipped);

        backend.aesCreatable = true;
        assertEquals("1234", getString("pin"));
        assertTrue("migrated once the keystore works", store.map.get("pin").startsWith("v2:"));
        assertEquals("migrated key no longer skipped", 1, secureStore.diagnostics().migrationSkipped);
        assertEquals("abc", getString("plain"));
        assertEquals(0, secureStore.diagnostics().migrationSkipped);
    }

    @Test
    public void migrationSkippedForgetsKeysThatSetRemoveOrClearReplaced() throws Exception {
        legacyStore.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        legacyStore.map.put("b", Fakes.androidDefaultBase64(utf8("2")));
        legacyStore.map.put("c", Fakes.androidDefaultBase64(utf8("3")));
        store.failWrites = true;
        assertEquals("1", getString("a"));
        assertEquals("2", getString("b"));
        assertEquals("3", getString("c"));
        assertEquals(3, secureStore.diagnostics().migrationSkipped);
        store.failWrites = false;

        secureStore.set("a", utf8("new"));
        assertEquals("set rewrote a", 2, secureStore.diagnostics().migrationSkipped);
        assertTrue(secureStore.remove("b"));
        assertEquals("remove deleted b", 1, secureStore.diagnostics().migrationSkipped);
        assertTrue(secureStore.clear());
        assertEquals("clear deleted c", 0, secureStore.diagnostics().migrationSkipped);
    }

    @Test
    public void failedSetKeepsTheKeyInMigrationSkipped() throws Exception {
        legacyStore.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        store.failWrites = true;
        assertEquals("1", getString("a"));
        try {
            secureStore.set("a", utf8("new"));
            fail("set must throw");
        } catch (StorageException expected) {}

        assertEquals("legacy entry still stored", 1, secureStore.diagnostics().migrationSkipped);
    }

    @Test
    public void legacyReadSucceedsWhenWriteBackFails() throws Exception {
        String legacy = Fakes.androidDefaultBase64(utf8("1234"));
        legacyStore.map.put("pin", legacy);
        store.failWrites = true;

        assertEquals("1234", getString("pin"));
        assertEquals(legacy, legacyStore.map.get("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
        assertEquals(1, secureStore.diagnostics().migrationSkipped);
    }

    // Verified migration and self-test

    private int selfTestEncryptions() {
        String selfTestAad = new String(SecureStore.SELF_TEST_AAD, StandardCharsets.UTF_8);
        int count = 0;
        for (String aad : backend.aesEncryptAads) {
            if (aad.equals(selfTestAad)) {
                count++;
            }
        }
        return count;
    }

    @Test
    public void legacyEntryIsKeptAndReadableWhenAesDecryptFails() throws Exception {
        backend.createRsaKey();
        String rsa = backend.upstreamRsaEncrypt(utf8("1234"));
        String plain = Fakes.androidDefaultBase64(utf8("abc"));
        legacyStore.map.put("pin", rsa);
        legacyStore.map.put("plain", plain);
        backend.aesDecryptAlwaysThrows = new AEADBadTagException("Tag mismatch");

        assertEquals("1234", getString("pin"));
        assertEquals("abc", getString("plain"));
        sweepExecutor.runAll();
        assertEquals("legacy entry unchanged", rsa, legacyStore.map.get("pin"));
        assertEquals("legacy entry unchanged", plain, legacyStore.map.get("plain"));
        assertEquals("still readable", "1234", getString("pin"));
        assertEquals("still readable", "abc", getString("plain"));

        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(0, diagnostics.migrated);
        assertEquals(2, diagnostics.migrationSkipped);
        assertEquals("a skipped migration is not a read failure", 0, diagnostics.lostItems);
        assertEquals(0, diagnostics.decryptFailures);
    }

    @Test
    public void legacyEntryIsKeptWhenItsNewBlobDoesNotDecrypt() throws Exception {
        String legacy = Fakes.androidDefaultBase64(utf8("1234"));
        legacyStore.map.put("pin", legacy);
        legacyStore.map.put("other", Fakes.androidDefaultBase64(utf8("5678")));
        backend.aesDecryptBadTagForAad = SecureStore.aad("pin");

        assertEquals("1234", getString("pin"));
        assertEquals(legacy, legacyStore.map.get("pin"));
        assertEquals("1234", getString("pin"));
        assertEquals("5678", getString("other"));
        assertTrue("self-test passed, other keys migrate", store.map.get("other").startsWith("v2:"));
        assertEquals(1, secureStore.diagnostics().migrated);
        assertEquals(1, secureStore.diagnostics().migrationSkipped);
    }

    @Test
    public void setRejectsWhenTheNewBlobDecryptsToOtherBytes() throws Exception {
        backend.aesDecryptCorruptsForAad = SecureStore.aad("pin");

        try {
            secureStore.set("pin", utf8("1234"));
            fail("set must reject a value that does not decrypt back");
        } catch (StorageException expected) {
            // fail closed
        }
        assertFalse("nothing is written", store.map.containsKey("pin"));
    }

    @Test
    public void setRejectsWhenTheNewBlobDoesNotDecrypt() throws Exception {
        backend.aesDecryptBadTagForAad = SecureStore.aad("pin");

        try {
            secureStore.set("pin", utf8("1234"));
            fail("set must reject a value that does not decrypt back");
        } catch (StorageException expected) {
            // fail closed
        }
        assertFalse("nothing is written", store.map.containsKey("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
    }

    @Test
    public void legacyEntryIsKeptWhenItsNewBlobDecryptsToOtherBytes() throws Exception {
        String legacy = Fakes.androidDefaultBase64(utf8("1234"));
        legacyStore.map.put("pin", legacy);
        backend.aesDecryptCorruptsForAad = SecureStore.aad("pin");

        assertEquals("1234", getString("pin"));
        assertEquals(legacy, legacyStore.map.get("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
        assertEquals(1, secureStore.diagnostics().migrationSkipped);
    }

    @Test
    public void selfTestRunsOnceBeforeTheFirstMigrationWrite() throws Exception {
        legacyStore.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        legacyStore.map.put("b", Fakes.androidDefaultBase64(utf8("2")));
        legacyStore.map.put("c", Fakes.androidDefaultBase64(utf8("3")));

        assertEquals("1", getString("a"));
        assertEquals(new String(SecureStore.SELF_TEST_AAD, StandardCharsets.UTF_8), backend.aesEncryptAads.get(0));
        sweepExecutor.runAll();
        secureStore.set("d", utf8("4"));

        assertEquals(1, selfTestEncryptions());
        assertEquals(3, secureStore.diagnostics().migrated);
    }

    @Test
    public void setDoesNotRunTheSelfTest() throws Exception {
        secureStore.set("a", utf8("1"));
        assertEquals(Arrays.asList("v2:a"), backend.aesEncryptAads);
    }

    @Test
    public void failedSelfTestStopsTheSweepAndIsRetriedLater() throws Exception {
        String a = Fakes.androidDefaultBase64(utf8("1"));
        String b = Fakes.androidDefaultBase64(utf8("2"));
        legacyStore.map.put("a", a);
        legacyStore.map.put("b", b);
        backend.aesDecryptAlwaysThrows = new AEADBadTagException("Tag mismatch");

        secureStore.contains("a");
        sweepExecutor.runAll();
        assertEquals("sweep stops after the first failed self-test", 1, selfTestEncryptions());
        assertEquals(a, legacyStore.map.get("a"));
        assertEquals(b, legacyStore.map.get("b"));

        try {
            secureStore.set("c", utf8("3"));
            fail("set fails closed while the keystore cannot decrypt what it encrypts");
        } catch (StorageException expected) {
            // the round-trip check rejects the write
        }
        assertFalse("nothing is written for c", store.map.containsKey("c"));

        backend.aesDecryptAlwaysThrows = null;
        assertEquals("1", getString("a"));
        assertTrue("migrated once the self-test passes", store.map.get("a").startsWith("v2:"));
        assertEquals(2, selfTestEncryptions());
    }

    // Fail-closed writes

    @Test
    public void setFailsClosedWhenAesKeyCannotBeCreated() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("old"));
        legacyStore.map.put("pin", legacy);
        backend.aesCreatable = false;

        try {
            secureStore.set("pin", utf8("new"));
            fail("set must throw");
        } catch (StorageException expected) {}
        try {
            secureStore.set("other", utf8("new"));
            fail("set must throw");
        } catch (StorageException expected) {}

        assertEquals("previous value untouched", legacy, legacyStore.map.get("pin"));
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

    // Retry classes per path

    @Test
    public void aesDecryptIllegalBlockSizeIsRetried() throws Exception {
        secureStore.set("pin", utf8("1234"));
        backend.aesDecryptErrors.add(new IllegalBlockSizeException());

        assertEquals("1234", getString("pin"));
        assertEquals(Arrays.asList(50L), sleeper.sleeps);
        assertEquals(0, secureStore.diagnostics().decryptFailures);
    }

    @Test
    public void aesEncryptIllegalBlockSizeIsRetried() throws Exception {
        backend.aesEncryptErrors.add(new IllegalBlockSizeException());
        backend.aesEncryptErrors.add(new IllegalBlockSizeException());

        secureStore.set("pin", utf8("1234"));
        assertEquals(Arrays.asList(50L, 200L), sleeper.sleeps);
        assertEquals("1234", getString("pin"));
    }

    @Test
    public void aesDecryptPlainBadPaddingIsRetried() throws Exception {
        secureStore.set("pin", utf8("1234"));
        backend.aesDecryptErrors.add(new BadPaddingException());

        assertEquals("1234", getString("pin"));
        assertEquals(Arrays.asList(50L), sleeper.sleeps);
    }

    @Test
    public void aesDecryptIllegalBlockSizeAfterAllRetriesIsUnreadableNotLost() throws Exception {
        secureStore.set("pin", utf8("1234"));
        String stored = store.map.get("pin");
        for (int i = 0; i < 3; i++) {
            backend.aesDecryptErrors.add(new IllegalBlockSizeException());
        }

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(Arrays.asList(50L, 200L), sleeper.sleeps);
        assertEquals(stored, store.map.get("pin"));
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(1, diagnostics.decryptFailures);
        assertEquals(0, diagnostics.lostItems);
        assertEquals("next read works", "1234", getString("pin"));
    }

    @Test
    public void aesBadTagWithTransientKeystoreCauseIsRetried() throws Exception {
        secureStore.set("pin", utf8("1234"));
        backend.aesDecryptErrors.add(Fakes.withTransientCause(new AEADBadTagException()));

        assertEquals("1234", getString("pin"));
        assertEquals(Arrays.asList(50L), sleeper.sleeps);
        assertEquals(0, secureStore.diagnostics().lostItems);
    }

    @Test
    public void rsaIllegalBlockSizeStaysPermanentAndFallsThroughToPlaintext() throws Exception {
        backend.createRsaKey();
        String value = repeat("a", 256);
        legacyStore.map.put("long", Fakes.androidDefaultBase64(utf8(value)));
        backend.rsaDecryptErrors.add(new IllegalBlockSizeException());

        assertEquals(value, getString("long"));
        assertTrue("not retried", sleeper.sleeps.isEmpty());
    }

    @Test
    public void rsaIllegalBlockSizeWithTransientKeystoreCauseIsRetried() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
        backend.rsaDecryptErrors.add(Fakes.withTransientCause(new IllegalBlockSizeException()));

        assertEquals("1234", getString("pin"));
        assertEquals(Arrays.asList(50L), sleeper.sleeps);
    }

    @Test
    public void rsaIllegalBlockSizeOnCiphertextIsRetried() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
        backend.rsaDecryptErrors.add(new IllegalBlockSizeException());

        assertEquals("1234", getString("pin"));
        assertEquals(Arrays.asList(50L), sleeper.sleeps);
        assertTrue("migrated", store.map.get("pin").startsWith("v2:"));
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(1, diagnostics.migrated);
        assertEquals(0, diagnostics.decryptFailures);
        assertEquals(0, diagnostics.lostItems);
    }

    @Test
    public void rsaIllegalBlockSizeOnCiphertextAfterAllRetriesIsUnreadableNotLost() throws Exception {
        backend.createRsaKey();
        String legacy = backend.upstreamRsaEncrypt(utf8("1234"));
        legacyStore.map.put("pin", legacy);
        for (int i = 0; i < 3; i++) {
            backend.rsaDecryptErrors.add(new IllegalBlockSizeException());
        }

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(Arrays.asList(50L, 200L), sleeper.sleeps);
        assertEquals("entry kept", legacy, legacyStore.map.get("pin"));
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(1, diagnostics.decryptFailures);
        assertEquals(0, diagnostics.lostItems);
        assertEquals("next read works", "1234", getString("pin"));
    }

    @Test
    public void rsaBadPaddingOnCiphertextIsLostWithoutRetry() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
        backend.rsaDecryptErrors.add(new BadPaddingException());

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertTrue("not retried", sleeper.sleeps.isEmpty());
        assertEquals(1, secureStore.diagnostics().lostItems);
        assertEquals(0, secureStore.diagnostics().decryptFailures);
    }

    // Single attempt while the AES path is failing

    @Test
    public void brokenKeystoreAddsRetrySleepsToOneLegacyGetOnly() throws Exception {
        legacyStore.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        legacyStore.map.put("b", Fakes.androidDefaultBase64(utf8("2")));
        backend.aesCreatable = false;

        assertEquals("1", getString("a"));
        assertEquals("first migration retries", Arrays.asList(50L, 200L), sleeper.sleeps);
        assertEquals("2", getString("b"));
        assertEquals("1", getString("a"));
        assertEquals("later migrations make one attempt", Arrays.asList(50L, 200L), sleeper.sleeps);
        assertEquals(2, secureStore.diagnostics().migrationSkipped);

        try {
            secureStore.set("c", utf8("3"));
            fail("set must throw");
        } catch (StorageException expected) {}
        assertEquals("set still retries", Arrays.asList(50L, 200L, 50L, 200L), sleeper.sleeps);

        backend.aesCreatable = true;
        assertEquals("1", getString("a"));
        assertTrue("one attempt still migrates once the keystore works", store.map.get("a").startsWith("v2:"));
    }

    @Test
    public void sweepMakesSingleAttemptsAfterAFailedEncrypt() throws Exception {
        backend.createRsaKey();
        String rsa = backend.upstreamRsaEncrypt(utf8("one"));
        String plain = Fakes.androidDefaultBase64(utf8("two"));
        legacyStore.map.put("rsa", rsa);
        legacyStore.map.put("plain", plain);
        backend.aesCreatable = false;
        try {
            secureStore.set("x", utf8("3"));
            fail("set must throw");
        } catch (StorageException expected) {}
        sleeper.sleeps.clear();

        backend.transientFailures = 1;
        sweepExecutor.runAll();

        assertTrue("no retry sleeps in the sweep", sleeper.sleeps.isEmpty());
        assertEquals(rsa, legacyStore.map.get("rsa"));
        assertEquals(plain, legacyStore.map.get("plain"));
    }

    private void failSetSoTheAesPathIsFailing() {
        backend.aesCreatable = false;
        try {
            secureStore.set("x", utf8("3"));
            fail("set must throw");
        } catch (StorageException expected) {}
        sleeper.sleeps.clear();
    }

    @Test
    public void singleAttemptSweepDoesNotCountATransientRsaDecryptFailure() throws Exception {
        backend.createRsaKey();
        String rsa = backend.upstreamRsaEncrypt(utf8("one"));
        legacyStore.map.put("rsa", rsa);
        failSetSoTheAesPathIsFailing();

        backend.rsaDecryptErrors.add(new KeyStoreException("Keystore busy"));
        sweepExecutor.runAll();

        assertTrue("no retry sleeps in the sweep", sleeper.sleeps.isEmpty());
        assertEquals(rsa, legacyStore.map.get("rsa"));
        assertEquals(0, secureStore.diagnostics().decryptFailures);
        assertEquals("a later get reads the key", "one", getString("rsa"));
        assertEquals(0, secureStore.diagnostics().decryptFailures);
        assertEquals(0, secureStore.diagnostics().lostItems);
    }

    @Test
    public void singleAttemptSweepDoesNotCountATransientRsaKeyLookupFailure() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("rsa", backend.upstreamRsaEncrypt(utf8("one")));
        failSetSoTheAesPathIsFailing();

        backend.transientFailures = 1;
        sweepExecutor.runAll();

        assertEquals(0, backend.transientFailures);
        assertEquals(0, secureStore.diagnostics().decryptFailures);
        assertEquals("a later get reads the key", "one", getString("rsa"));
        assertEquals(0, secureStore.diagnostics().decryptFailures);
    }

    @Test
    public void singleAttemptSweepStillCountsAPermanentRsaFailure() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("rsa", backend.upstreamRsaEncrypt(utf8("one")));
        failSetSoTheAesPathIsFailing();

        backend.rsaDecryptErrors.add(new BadPaddingException());
        sweepExecutor.runAll();

        assertEquals(1, secureStore.diagnostics().lostItems);
    }

    @Test
    public void successfulSetRestoresRetriesForMigration() throws Exception {
        legacyStore.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        backend.aesCreatable = false;
        try {
            secureStore.set("x", utf8("3"));
            fail("set must throw");
        } catch (StorageException expected) {}
        backend.aesCreatable = true;
        secureStore.set("y", utf8("4"));
        sleeper.sleeps.clear();

        backend.aesEncryptErrors.add(new IllegalBlockSizeException());
        assertEquals("1", getString("a"));
        assertEquals(Arrays.asList(50L), sleeper.sleeps);
        assertTrue(store.map.get("a").startsWith("v2:"));
    }

    // Sweep

    @Test
    public void sweepMigratesAllLegacyEntriesOnceInTheBackground() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("rsa", backend.upstreamRsaEncrypt(utf8("one")));
        legacyStore.map.put("plain", Fakes.androidDefaultBase64(utf8("two")));
        legacyStore.map.put("garbage", "%%%");
        secureStore.set("v2", utf8("three"));
        String v2 = store.map.get("v2");

        assertEquals("sweep is queued, not run inline", 1, sweepExecutor.tasks.size());
        assertFalse(store.map.containsKey("rsa"));
        sweepExecutor.runAll();

        assertTrue(store.map.get("rsa").startsWith("v2:"));
        assertTrue(store.map.get("plain").startsWith("v2:"));
        assertEquals("v2 entries untouched", v2, store.map.get("v2"));
        assertEquals("garbage kept", "%%%", legacyStore.map.get("garbage"));
        assertEquals(2, secureStore.diagnostics().migrated);
        assertEquals("one", getString("rsa"));
        assertEquals("two", getString("plain"));

        secureStore.get("rsa");
        assertTrue("sweep starts only once", sweepExecutor.tasks.isEmpty());
    }

    @Test
    public void sweepDoesNotOverwriteNewerValue() throws Exception {
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("old")));
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

    @Test
    public void legacyRsaEntryMigratesIntoV2AndStaysInTheLegacyFileUnchanged() throws Exception {
        backend.createRsaKey();
        String rsa = backend.upstreamRsaEncrypt(utf8("1234"));
        legacyStore.map.put("pin", rsa);

        assertEquals("1234", getString("pin"));
        assertEquals("1234", getString("pin"));

        assertTrue(store.map.get("pin").startsWith("v2:"));
        assertEquals("legacy entry unchanged", rsa, legacyStore.map.get("pin"));
        assertEquals(0, legacyStore.writes);
        assertEquals(0, legacyStore.removes);
        assertEquals(0, legacyStore.fileDeletions);
        assertTrue("RSA key kept", backend.hasRsaKey());
        assertEquals(0, backend.rsaKeysDeleted);
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(1, diagnostics.migrated);
        assertEquals("distinct keys", 1, diagnostics.legacyEntriesKept);
    }

    @Test
    public void setWritesOnlyTheV2File() throws Exception {
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("old")));
        Map<String, String> legacyBefore = new HashMap<>(legacyStore.map);

        secureStore.set("pin", utf8("new"));
        secureStore.set("other", utf8("value"));

        assertEquals(legacyBefore, legacyStore.map);
        assertEquals(0, legacyStore.writes);
        assertEquals(0, legacyStore.removes);
        assertTrue(store.map.get("pin").startsWith("v2:"));
        assertTrue(store.map.get("other").startsWith("v2:"));
        assertEquals("new", getString("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
        assertEquals(0, secureStore.diagnostics().legacyEntriesKept);
    }

    @Test
    public void getAfterMigrationReadsV2EvenIfTheLegacyEntryChanges() throws Exception {
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("old")));
        assertEquals("old", getString("pin"));

        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("changed")));
        assertEquals("old", getString("pin"));

        legacyStore.map.remove("pin");
        assertEquals("old", getString("pin"));
        assertEquals(1, secureStore.diagnostics().migrated);
    }

    @Test
    public void unreadableV2EntryDoesNotFallBackToTheLegacyEntry() throws Exception {
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("old")));
        store.map.put("pin", "v2:" + Base64.getEncoder().encodeToString(new byte[40]));

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(0, secureStore.diagnostics().migrated);
    }

    @Test
    public void v2EntryInTheLegacyFileFromAnEarlierBuildIsMigrated() throws Exception {
        secureStore.set("pin", utf8("1234"));
        String earlier = store.map.remove("pin");
        legacyStore.map.put("pin", earlier);

        assertEquals("1234", getString("pin"));
        assertTrue(store.map.get("pin").startsWith("v2:"));
        assertEquals(earlier, legacyStore.map.get("pin"));
        assertEquals(1, secureStore.diagnostics().migrated);
    }

    @Test
    public void removeDeletesTheKeyFromBothFiles() throws Exception {
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("1234")));
        legacyStore.map.put("legacyOnly", Fakes.androidDefaultBase64(utf8("abc")));
        secureStore.set("v2Only", utf8("xyz"));
        assertEquals("1234", getString("pin"));
        assertEquals(1, secureStore.diagnostics().legacyEntriesKept);

        assertTrue(secureStore.remove("pin"));
        assertTrue(secureStore.remove("legacyOnly"));
        assertTrue(secureStore.remove("v2Only"));

        assertTrue(store.map.isEmpty());
        assertTrue(legacyStore.map.isEmpty());
        assertFalse(secureStore.contains("pin"));
        assertEquals(SecureStore.Status.NOT_FOUND, secureStore.get("pin").status);
        assertEquals(0, secureStore.diagnostics().legacyEntriesKept);
        assertEquals("the legacy file is not deleted", 0, legacyStore.fileDeletions);
        assertEquals("the RSA alias is not deleted", 0, backend.rsaKeysDeleted);
    }

    @Test
    public void removeReportsAFailedLegacyDelete() throws Exception {
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("1234")));
        store.failWrites = true;
        assertEquals("1234", getString("pin"));
        assertEquals(1, secureStore.diagnostics().migrationSkipped);
        legacyStore.failRemoves = true;

        assertFalse(secureStore.remove("pin"));
        assertEquals("legacy entry still stored", 1, secureStore.diagnostics().migrationSkipped);
    }

    @Test
    public void clearClearsBothFilesAndKeepsTheKeys() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("rsa", backend.upstreamRsaEncrypt(utf8("one")));
        legacyStore.map.put("plain", Fakes.androidDefaultBase64(utf8("two")));
        assertEquals("one", getString("rsa"));
        secureStore.set("v2", utf8("three"));

        assertTrue(secureStore.clear());

        assertTrue(store.map.isEmpty());
        assertTrue(legacyStore.map.isEmpty());
        assertEquals(0, secureStore.keys().length);
        assertEquals(0, secureStore.diagnostics().legacyEntriesKept);
        assertTrue(backend.hasAesKey());
        assertTrue(backend.hasRsaKey());
        assertEquals(0, legacyStore.fileDeletions);
    }

    @Test
    public void clearDoesNotTouchAnEmptyLegacyFile() throws Exception {
        secureStore.set("a", utf8("1"));
        assertTrue(secureStore.clear());
        assertEquals(0, legacyStore.clears);
        assertEquals(1, store.clears);
    }

    @Test
    public void keysAndContainsCoverBothFiles() throws Exception {
        legacyStore.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        legacyStore.map.put("b", Fakes.androidDefaultBase64(utf8("2")));
        secureStore.set("b", utf8("2"));
        secureStore.set("c", utf8("3"));

        String[] keys = secureStore.keys();
        Arrays.sort(keys);
        assertArrayEquals(new String[] { "a", "b", "c" }, keys);
        assertTrue(secureStore.contains("a"));
        assertTrue(secureStore.contains("c"));
        assertFalse(secureStore.contains("d"));
    }

    @Test
    public void sweepMigratesIntoV2AndLeavesTheLegacyFileIntact() throws Exception {
        backend.createRsaKey();
        String lost = backend.upstreamRsaEncrypt(utf8("lost"));
        backend.createRsaKey();
        legacyStore.map.put("rsa", backend.upstreamRsaEncrypt(utf8("one")));
        legacyStore.map.put("plain", Fakes.androidDefaultBase64(utf8("two")));
        legacyStore.map.put("garbage", "%%%");
        legacyStore.map.put("lost", lost);
        Map<String, String> legacyBefore = new HashMap<>(legacyStore.map);

        secureStore.contains("x");
        sweepExecutor.runAll();

        assertEquals(legacyBefore, legacyStore.map);
        assertEquals(0, legacyStore.writes);
        assertEquals(0, legacyStore.removes);
        assertEquals(0, legacyStore.fileDeletions);
        assertEquals(0, backend.rsaKeysDeleted);
        assertTrue(store.map.get("rsa").startsWith("v2:"));
        assertTrue(store.map.get("plain").startsWith("v2:"));
        assertFalse(store.map.containsKey("garbage"));
        assertFalse(store.map.containsKey("lost"));
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(2, diagnostics.migrated);
        assertEquals(2, diagnostics.legacyEntriesKept);
        assertEquals(1, diagnostics.lostItems);
        assertEquals(1, diagnostics.decryptFailures);
    }

    @Test
    public void sweepSkipsLegacyEntriesThatAlreadyHaveAV2Entry() throws Exception {
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("old")));
        assertEquals("old", getString("pin"));
        int encryptions = backend.aesEncryptCalls;

        sweepExecutor.runAll();

        assertEquals(encryptions, backend.aesEncryptCalls);
        assertEquals(1, secureStore.diagnostics().migrated);
    }

    @Test
    public void deletionOnDeletesTheLegacyEntryAndThenTheRsaKeyAndTheLegacyFile() throws Exception {
        deleteLegacyStorage();
        backend.createRsaKey();
        legacyStore.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
        legacyStore.map.put("other", Fakes.androidDefaultBase64(utf8("abc")));

        assertEquals("1234", getString("pin"));
        assertFalse(legacyStore.map.containsKey("pin"));
        assertTrue("other legacy entries need the RSA key", backend.hasRsaKey());
        assertEquals(0, legacyStore.fileDeletions);

        assertEquals("abc", getString("other"));
        assertTrue(legacyStore.map.isEmpty());
        assertFalse(backend.hasRsaKey());
        assertEquals(1, backend.rsaKeysDeleted);
        assertEquals(1, legacyStore.fileDeletions);

        assertEquals("1234", getString("pin"));
        assertEquals("abc", getString("other"));
        assertTrue(secureStore.remove("pin"));
        sweepExecutor.runAll();
        assertEquals("deleted once", 1, legacyStore.fileDeletions);
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(2, diagnostics.migrated);
        assertEquals(0, diagnostics.legacyEntriesKept);
    }

    @Test
    public void deletionOnKeepsLegacyEntriesThatWereNotMigrated() throws Exception {
        deleteLegacyStorage();
        backend.createRsaKey();
        String lost = backend.upstreamRsaEncrypt(utf8("lost"));
        backend.createRsaKey();
        String skipped = Fakes.androidDefaultBase64(utf8("1234"));
        legacyStore.map.put("lost", lost);
        legacyStore.map.put("garbage", "%%%");
        legacyStore.map.put("skipped", skipped);
        backend.aesDecryptBadTagForAad = SecureStore.aad("skipped");

        secureStore.contains("x");
        sweepExecutor.runAll();
        assertEquals("1234", getString("skipped"));

        assertEquals(lost, legacyStore.map.get("lost"));
        assertEquals("%%%", legacyStore.map.get("garbage"));
        assertEquals(skipped, legacyStore.map.get("skipped"));
        assertTrue(backend.hasRsaKey());
        assertEquals(0, backend.rsaKeysDeleted);
        assertEquals(0, legacyStore.fileDeletions);
        assertEquals(1, secureStore.diagnostics().migrationSkipped);
    }

    @Test
    public void deletionOnSetDeletesTheLegacyEntry() throws Exception {
        deleteLegacyStorage();
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("old")));

        secureStore.set("pin", utf8("new"));

        assertTrue(legacyStore.map.isEmpty());
        assertEquals(1, legacyStore.fileDeletions);
        assertEquals("new", getString("pin"));
    }

    @Test
    public void deletionOnCleansUpWhatTheMigrationReleaseKept() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("rsa", backend.upstreamRsaEncrypt(utf8("one")));
        legacyStore.map.put("plain", Fakes.androidDefaultBase64(utf8("two")));
        legacyStore.map.put("stale", Fakes.androidDefaultBase64(utf8("old")));
        secureStore.contains("x");
        sweepExecutor.runAll();
        secureStore.set("stale", utf8("new"));
        assertEquals(3, legacyStore.map.size());

        deleteLegacyStorage();
        secureStore.contains("x");
        sweepExecutor.runAll();

        assertTrue(legacyStore.map.isEmpty());
        assertFalse(backend.hasRsaKey());
        assertEquals(1, legacyStore.fileDeletions);
        assertEquals("one", getString("rsa"));
        assertEquals("two", getString("plain"));
        assertEquals("new", getString("stale"));
    }

    @Test
    public void deletionOnGetOfAV2EntryDeletesItsLegacyCopy() throws Exception {
        legacyStore.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        legacyStore.map.put("b", Fakes.androidDefaultBase64(utf8("2")));
        assertEquals("1", getString("a"));

        deleteLegacyStorage();
        assertEquals("1", getString("a"));

        assertFalse(legacyStore.map.containsKey("a"));
        assertTrue(legacyStore.map.containsKey("b"));
        assertEquals(0, legacyStore.fileDeletions);
    }

    @Test
    public void deletionOnKeepsCountingALegacyEntryWhoseDeleteFailed() throws Exception {
        deleteLegacyStorage();
        legacyStore.map.put("pin", Fakes.androidDefaultBase64(utf8("1234")));
        legacyStore.failRemoves = true;

        assertEquals("1234", getString("pin"));

        assertTrue(legacyStore.map.containsKey("pin"));
        assertEquals(1, secureStore.diagnostics().legacyEntriesKept);
        assertEquals(0, legacyStore.fileDeletions);

        legacyStore.failRemoves = false;
        assertEquals("1234", getString("pin"));
        assertEquals(0, secureStore.diagnostics().legacyEntriesKept);
        assertEquals(1, legacyStore.fileDeletions);
    }

    @Test
    public void deletionOnKeepsTheLegacyFileWhenTheRsaKeyCannotBeDeleted() throws Exception {
        deleteLegacyStorage();
        backend.createRsaKey();
        legacyStore.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
        backend.deleteRsaKeyThrows = new KeyStoreException("Keystore busy");

        assertEquals("1234", getString("pin"));
        assertTrue(legacyStore.map.isEmpty());
        assertTrue(backend.hasRsaKey());
        assertEquals(0, legacyStore.fileDeletions);

        backend.deleteRsaKeyThrows = null;
        sweepExecutor.runAll();
        assertFalse(backend.hasRsaKey());
        assertEquals(1, legacyStore.fileDeletions);
    }

    @Test
    public void deletionOnWithoutLegacyDataOnlyDeletesTheEmptyLegacyFile() throws Exception {
        deleteLegacyStorage();
        secureStore.set("a", utf8("1"));
        sweepExecutor.runAll();

        assertEquals(1, legacyStore.fileDeletions);
        assertEquals(0, backend.rsaKeysDeleted);
        assertEquals("1", getString("a"));
    }

    @Test
    public void productionConfigurationKeepsTheLegacyStorage() throws Exception {
        backend.createRsaKey();
        legacyStore.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
        secureStore = newSecureStore(SecureStore.DELETE_LEGACY_STORAGE);

        assertEquals("1234", getString("pin"));
        sweepExecutor.runAll();

        assertTrue(legacyStore.map.containsKey("pin"));
        assertTrue(backend.hasRsaKey());
        assertEquals(0, legacyStore.fileDeletions);
    }
}
