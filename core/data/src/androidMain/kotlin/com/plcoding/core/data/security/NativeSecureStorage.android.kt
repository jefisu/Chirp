package com.plcoding.core.data.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.security.SecureStorage
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private val Context.secureDataStore: DataStore<Preferences> by preferencesDataStore(name = "secure_preferences")

actual class NativeSecureStorage(
    private val context: Context,
    private val logger: ChirpLogger
) : SecureStorage {

    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private val secretKey: SecretKey
        get() = getOrCreateSecretKey()

    actual override suspend fun saveString(key: String, value: String) {
        try {
            val encryptedValue = encrypt(value)
            context.secureDataStore.edit { preferences ->
                preferences[stringPreferencesKey(key)] = encryptedValue
            }
        } catch (e: Exception) {
            logger.error("Failed to save encrypted data for key: $key", e)
        }
    }

    actual override suspend fun getString(key: String): String? {
        return try {
            context.secureDataStore.data
                .map { preferences -> preferences[stringPreferencesKey(key)] }
                .first()
                ?.let { decrypt(it) }
        } catch (e: Exception) {
            logger.error("Failed to retrieve encrypted data for key: $key", e)
            null
        }
    }

    actual override suspend fun remove(key: String) {
        try {
            context.secureDataStore.edit { preferences ->
                preferences.remove(stringPreferencesKey(key))
            }
        } catch (e: Exception) {
            logger.error("Failed to remove data for key: $key", e)
        }
    }

    actual override suspend fun clear() {
        try {
            context.secureDataStore.edit { preferences ->
                preferences.clear()
            }
        } catch (e: Exception) {
            logger.error("Failed to clear secure storage", e)
        }
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val existingKey = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existingKey != null) {
            return existingKey.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        val keySpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(keySpec)
        return keyGenerator.generateKey()
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val combined = iv + encrypted
        return Base64.getEncoder().encodeToString(combined)
    }

    private fun decrypt(encryptedValue: String): String? {
        return try {
            val combined = Base64.getDecoder().decode(encryptedValue)
            val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
            val encrypted = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))
            val decrypted = cipher.doFinal(encrypted)
            String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            logger.error("Failed to decrypt data", e)
            null
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "chirp_secure_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
    }
}
