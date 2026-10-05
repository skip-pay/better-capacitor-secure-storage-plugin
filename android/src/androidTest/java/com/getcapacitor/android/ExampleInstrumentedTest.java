package com.getcapacitor.android;

import static org.junit.Assert.*;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.whitestein.securestorage.SecureStoragePluginPlugin;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {

    private Context appContext;
    private SharedPreferences prefs;
    private String rsaAlias;
    private String aesAlias;

    @Before
    public void setUp() throws Exception {
        appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        prefs = appContext.getSharedPreferences("cap_sec", Context.MODE_PRIVATE);
        prefs.edit().clear().commit();
        rsaAlias = appContext.getPackageName() + "_cap_sec";
        aesAlias = appContext.getPackageName() + "_cap_sec_aes_v2";
    }

    private SecureStoragePluginPlugin newPlugin() {
        SecureStoragePluginPlugin plugin = new SecureStoragePluginPlugin();
        plugin.loadTextContext(appContext);
        return plugin;
    }

    private static KeyStore keyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return keyStore;
    }

    /** Creates the upstream RSA key pair with the upstream parameters, unless it exists. */
    private PublicKey ensureUpstreamRsaKey() throws Exception {
        KeyStore keyStore = keyStore();
        if (!keyStore.containsAlias(rsaAlias)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            generator.initialize(
                new KeyGenParameterSpec.Builder(rsaAlias, KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .build()
            );
            generator.generateKeyPair();
        }
        return keyStore().getCertificate(rsaAlias).getPublicKey();
    }

    /** Encrypts like upstream PasswordStorageHelper_SDK18.encrypt. */
    private static String upstreamRsaEncrypt(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        if (data.length <= 245) {
            return Base64.encodeToString(cipher.doFinal(data), Base64.DEFAULT);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int position = 0; position < data.length; position += 245) {
            out.write(cipher.doFinal(data, position, Math.min(245, data.length - position)));
        }
        return Base64.encodeToString(out.toByteArray(), Base64.DEFAULT);
    }

    private static String repeat(String part, int times) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < times; i++) {
            builder.append(part);
        }
        return builder.toString();
    }

    @Test
    public void useAppContext() throws Exception {
        assertEquals("com.whitestein.securestorage.test", appContext.getPackageName());
    }

    @Test
    public void setTest() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        JSObject result = plugin._set("test", "test value");
        assertTrue(result.getBoolean("value"));
    }

    @Test
    public void getTest() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        plugin._set("test", "test value");
        JSObject result = plugin._get("test");
        assertEquals("test value", result.getString("value"));
    }

    @Test
    public void keysTest() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        JSObject result = plugin._set("test", "test value");
        assertTrue(result.getBoolean("value"));
        result = plugin._set("test2", "test value");
        assertTrue(result.getBoolean("value"));

        result = plugin._keys();
        JSArray keys = (JSArray) result.get("value");
        assertEquals(2, keys.length());
        assertTrue(keys.toList().contains("test"));
        assertTrue(keys.toList().contains("test2"));
    }

    @Test(expected = Exception.class)
    public void getNonExistingKeyTest() throws Exception {
        newPlugin()._get("testNonExisting");
    }

    @Test(expected = Exception.class)
    public void removeTest() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        plugin._set("test", "test value");
        plugin._get("test");
        JSObject result = plugin._remove("test");
        assertTrue(result.getBoolean("value"));

        plugin._get("test");
    }

    @Test(expected = Exception.class)
    public void clearTest() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        plugin._set("test", "test value");
        plugin._set("test2", "test value");
        plugin._clear();
        plugin._get("test");
    }

    @Test(expected = Exception.class)
    public void clearTest2() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        plugin._set("test", "test value");
        plugin._set("test2", "test value");
        plugin._clear();
        plugin._get("test2");
    }

    @Test
    public void getPlatformTest() throws Exception {
        assertEquals("android", newPlugin()._getPlatform().getString("value"));
    }

    @Test
    public void keystoreRoundTripWritesV2Format() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        String large = repeat("0123456789", 1000);
        plugin._set("pin", "1234");
        plugin._set("large", large);
        plugin._set("unicode", "Příliš žluťoučký kůň 🐎");
        plugin._set("empty", "");

        String raw = prefs.getString("pin", null);
        assertTrue(raw.startsWith("v2:"));
        byte[] blob = Base64.decode(raw.substring(3), Base64.DEFAULT);
        assertEquals(12 + 4 + 16, blob.length);
        assertTrue(keyStore().containsAlias(aesAlias));

        SecureStoragePluginPlugin fresh = newPlugin();
        assertEquals("1234", fresh._get("pin").getString("value"));
        assertEquals(large, fresh._get("large").getString("value"));
        assertEquals("Příliš žluťoučký kůň 🐎", fresh._get("unicode").getString("value"));
        assertEquals("", fresh._get("empty").getString("value"));
        assertEquals("keystoreAes", fresh._getDiagnostics().getString("keyBackend"));
    }

    @Test
    public void blobMovedToAnotherKeyIsUnreadable() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        plugin._set("a", "secret");
        prefs.edit().putString("b", prefs.getString("a", null)).commit();
        try {
            plugin._get("b");
            fail("AAD must bind the blob to its key");
        } catch (Exception expected) {
            assertEquals("Item with given key does not exist", expected.getMessage());
        }
        assertEquals("secret", plugin._get("a").getString("value"));
        assertEquals(1, plugin._getDiagnostics().getInteger("lostItems").intValue());
    }

    @Test
    public void tamperedBlobIsUnreadableAndOverwritable() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        plugin._set("pin", "1234");
        byte[] blob = Base64.decode(prefs.getString("pin", null).substring(3), Base64.DEFAULT);
        blob[20] ^= 1;
        prefs.edit().putString("pin", "v2:" + Base64.encodeToString(blob, Base64.NO_WRAP)).commit();

        try {
            plugin._get("pin");
            fail("tampered blob must not decrypt");
        } catch (Exception expected) {}
        assertTrue(prefs.contains("pin"));
        assertTrue(keyStore().containsAlias(aesAlias));

        plugin._set("pin", "5678");
        assertEquals("5678", plugin._get("pin").getString("value"));
    }

    @Test
    public void legacyRsaIsReadAndMigratedToAes() throws Exception {
        PublicKey publicKey = ensureUpstreamRsaKey();
        String longValue = repeat("token-", 120);
        prefs
            .edit()
            .putString("pin", upstreamRsaEncrypt(publicKey, "1234".getBytes(StandardCharsets.UTF_8)))
            .putString("token", upstreamRsaEncrypt(publicKey, longValue.getBytes(StandardCharsets.UTF_8)))
            .commit();

        SecureStoragePluginPlugin plugin = newPlugin();
        assertEquals("1234", plugin._get("pin").getString("value"));
        assertEquals(longValue, plugin._get("token").getString("value"));
        assertTrue(prefs.getString("pin", null).startsWith("v2:"));
        assertTrue(prefs.getString("token", null).startsWith("v2:"));
        assertTrue("RSA key is kept for other legacy entries", keyStore().containsAlias(rsaAlias));

        SecureStoragePluginPlugin fresh = newPlugin();
        assertEquals("1234", fresh._get("pin").getString("value"));
        assertEquals(longValue, fresh._get("token").getString("value"));
    }

    @Test
    public void legacyPlaintextIsReadAndMigratedToAes() throws Exception {
        prefs.edit().putString("pin", Base64.encodeToString("1234".getBytes(StandardCharsets.UTF_8), Base64.DEFAULT)).commit();

        SecureStoragePluginPlugin plugin = newPlugin();
        assertEquals("1234", plugin._get("pin").getString("value"));
        assertTrue(prefs.getString("pin", null).startsWith("v2:"));
        assertEquals("1234", newPlugin()._get("pin").getString("value"));
    }

    @Test
    public void legacyEntryOutsideBase64IsUnreadable() throws Exception {
        // android.util.Base64 skips characters outside the alphabet instead of throwing.
        assertEquals(0, Base64.decode("%%%", Base64.DEFAULT).length);
        prefs.edit().putString("garbage", "%%%").putString("junk", "QUJD%").commit();

        SecureStoragePluginPlugin plugin = newPlugin();
        for (String key : new String[] { "garbage", "junk" }) {
            try {
                plugin._get(key);
                fail("must not read as a value: " + key);
            } catch (Exception expected) {
                assertEquals("Item with given key does not exist", expected.getMessage());
            }
        }
        assertEquals("%%%", prefs.getString("garbage", null));
        assertEquals(2, plugin._getDiagnostics().getInteger("decryptFailures").intValue());
    }

    @Test
    public void clearKeepsKeystoreKeys() throws Exception {
        SecureStoragePluginPlugin plugin = newPlugin();
        plugin._set("pin", "1234");
        plugin._clear();
        assertEquals(0, prefs.getAll().size());
        assertTrue(keyStore().containsAlias(aesAlias));
    }

    @Test
    public void diagnosticsHaveAllFields() throws Exception {
        JSObject diagnostics = newPlugin()._getDiagnostics();
        assertEquals(0, diagnostics.getInteger("parked").intValue());
        assertEquals(0, diagnostics.getInteger("duplicatesResolved").intValue());
        assertEquals(0, diagnostics.getInteger("plaintextFallbacks").intValue());
        assertEquals("n/a", diagnostics.getString("accessGroupMode"));
        assertNotNull(diagnostics.getInteger("migrated"));
        assertNotNull(diagnostics.getInteger("lostItems"));
        assertNotNull(diagnostics.getInteger("decryptFailures"));
        assertNotNull(diagnostics.getString("keyBackend"));
    }
}
