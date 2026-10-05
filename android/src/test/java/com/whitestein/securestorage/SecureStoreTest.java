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
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
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
        // android.util.Base64 decodes "%%%" to zero bytes without throwing, like the fake now does,
        // so this holds on a device only because the reader rejects non-base64 text itself.
        store.map.put("notBase64", "%%%");

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("bin").status);
        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("notBase64").status);
        assertEquals("%%%", store.map.get("notBase64"));
        assertEquals(2, secureStore.diagnostics().decryptFailures);
    }

    @Test
    public void legacyWithCharactersOutsideBase64IsUndecodable() {
        // On a device "QUJD%" decodes to "ABC" and "\n" to nothing.
        store.map.put("junk", Fakes.androidDefaultBase64(utf8("ABC")).trim() + "%");
        store.map.put("blank", "\n");

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
        store.map.put("pin", legacy);
        store.map.put("plain", Fakes.androidDefaultBase64(utf8("abc")));
        backend.aesCreatable = false;

        assertEquals("1234", getString("pin"));
        assertEquals("abc", getString("plain"));
        assertEquals("legacy entry kept", legacy, store.map.get("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
        assertEquals(2, secureStore.diagnostics().migrationSkipped);

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
        store.map.put("pin", rsa);
        store.map.put("plain", plain);
        backend.aesDecryptAlwaysThrows = new AEADBadTagException("Tag mismatch");

        assertEquals("1234", getString("pin"));
        assertEquals("abc", getString("plain"));
        sweepExecutor.runAll();
        assertEquals("legacy entry unchanged", rsa, store.map.get("pin"));
        assertEquals("legacy entry unchanged", plain, store.map.get("plain"));
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
        store.map.put("pin", legacy);
        store.map.put("other", Fakes.androidDefaultBase64(utf8("5678")));
        backend.aesDecryptBadTagForAad = SecureStore.aad("pin");

        assertEquals("1234", getString("pin"));
        assertEquals(legacy, store.map.get("pin"));
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
        store.map.put("pin", legacy);
        backend.aesDecryptCorruptsForAad = SecureStore.aad("pin");

        assertEquals("1234", getString("pin"));
        assertEquals(legacy, store.map.get("pin"));
        assertEquals(0, secureStore.diagnostics().migrated);
        assertEquals(1, secureStore.diagnostics().migrationSkipped);
    }

    @Test
    public void selfTestRunsOnceBeforeTheFirstMigrationWrite() throws Exception {
        store.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        store.map.put("b", Fakes.androidDefaultBase64(utf8("2")));
        store.map.put("c", Fakes.androidDefaultBase64(utf8("3")));

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
        store.map.put("a", a);
        store.map.put("b", b);
        backend.aesDecryptAlwaysThrows = new AEADBadTagException("Tag mismatch");

        secureStore.contains("a");
        sweepExecutor.runAll();
        assertEquals("sweep stops after the first failed self-test", 1, selfTestEncryptions());
        assertEquals(a, store.map.get("a"));
        assertEquals(b, store.map.get("b"));

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
        store.map.put("long", Fakes.androidDefaultBase64(utf8(value)));
        backend.rsaDecryptErrors.add(new IllegalBlockSizeException());

        assertEquals(value, getString("long"));
        assertTrue("not retried", sleeper.sleeps.isEmpty());
    }

    @Test
    public void rsaIllegalBlockSizeWithTransientKeystoreCauseIsRetried() throws Exception {
        backend.createRsaKey();
        store.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
        backend.rsaDecryptErrors.add(Fakes.withTransientCause(new IllegalBlockSizeException()));

        assertEquals("1234", getString("pin"));
        assertEquals(Arrays.asList(50L), sleeper.sleeps);
    }

    @Test
    public void rsaIllegalBlockSizeOnCiphertextIsRetried() throws Exception {
        backend.createRsaKey();
        store.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
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
        store.map.put("pin", legacy);
        for (int i = 0; i < 3; i++) {
            backend.rsaDecryptErrors.add(new IllegalBlockSizeException());
        }

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertEquals(Arrays.asList(50L, 200L), sleeper.sleeps);
        assertEquals("entry kept", legacy, store.map.get("pin"));
        SecureStore.Diagnostics diagnostics = secureStore.diagnostics();
        assertEquals(1, diagnostics.decryptFailures);
        assertEquals(0, diagnostics.lostItems);
        assertEquals("next read works", "1234", getString("pin"));
    }

    @Test
    public void rsaBadPaddingOnCiphertextIsLostWithoutRetry() throws Exception {
        backend.createRsaKey();
        store.map.put("pin", backend.upstreamRsaEncrypt(utf8("1234")));
        backend.rsaDecryptErrors.add(new BadPaddingException());

        assertEquals(SecureStore.Status.UNREADABLE, secureStore.get("pin").status);
        assertTrue("not retried", sleeper.sleeps.isEmpty());
        assertEquals(1, secureStore.diagnostics().lostItems);
        assertEquals(0, secureStore.diagnostics().decryptFailures);
    }

    // Single attempt while the AES path is failing

    @Test
    public void brokenKeystoreAddsRetrySleepsToOneLegacyGetOnly() throws Exception {
        store.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
        store.map.put("b", Fakes.androidDefaultBase64(utf8("2")));
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
        store.map.put("rsa", rsa);
        store.map.put("plain", plain);
        backend.aesCreatable = false;
        try {
            secureStore.set("x", utf8("3"));
            fail("set must throw");
        } catch (StorageException expected) {}
        sleeper.sleeps.clear();

        backend.transientFailures = 1;
        sweepExecutor.runAll();

        assertTrue("no retry sleeps in the sweep", sleeper.sleeps.isEmpty());
        assertEquals(rsa, store.map.get("rsa"));
        assertEquals(plain, store.map.get("plain"));
    }

    @Test
    public void successfulSetRestoresRetriesForMigration() throws Exception {
        store.map.put("a", Fakes.androidDefaultBase64(utf8("1")));
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
