@file:OptIn(ExperimentalEncodingApi::class)

package com.plcoding.core.data.security

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

expect object Crypto {
    fun encrypt(bytes: ByteArray): ByteArray
    fun decrypt(bytes: ByteArray): ByteArray
}

fun Crypto.encryptToBase64(bytes: ByteArray): String {
    val encryptedBytes = Crypto.encrypt(bytes)
    return Base64.encode(encryptedBytes)
}

fun Crypto.decryptFromBase64(encodedBase64: String): ByteArray {
    val encryptedBytes = Base64.decode(encodedBase64.encodeToByteArray())
    return Crypto.decrypt(encryptedBytes)
}