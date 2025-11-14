package com.plcoding.core.data.security

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

actual object Crypto {

    const val ALGORITHM = "AES"
    const val BLOCK_MODE = "GCM"
    const val PADDING = "NoPadding"
    const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    const val GCM_IV_LENGTH = 12 // bytes
    const val GCM_TAG_LENGTH = 128 // bits

    private val cipher = Cipher.getInstance(TRANSFORMATION)

    actual fun encrypt(bytes: ByteArray): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeyProvider.getKey())
        val iv = cipher.iv
        val encrypted = cipher.doFinal(bytes)
        return iv + encrypted
    }

    actual fun decrypt(bytes: ByteArray): ByteArray {
        val iv = bytes.copyOfRange(0, GCM_IV_LENGTH)
        val encrypted = bytes.copyOfRange(GCM_IV_LENGTH, bytes.size)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeyProvider.getKey(), spec)

        return cipher.doFinal(encrypted)
    }
}