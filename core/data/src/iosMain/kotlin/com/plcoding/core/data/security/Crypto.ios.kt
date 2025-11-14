@file:OptIn(ExperimentalForeignApi::class)

package com.plcoding.core.data.security

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytes
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFRangeMake
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnData
import platform.Security.kSecValueData
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

actual object Crypto {
    private const val SERVICE_NAME = "ChirpApp"

    private fun generateSecureId(): String {
        val randomBytes = ByteArray(16)
        randomBytes.usePinned { pinned ->
            SecRandomCopyBytes(kSecRandomDefault, 16u, pinned.addressOf(0))
        }

        val hexString = randomBytes.joinToString("") { byte ->
            val unsigned = byte.toUByte().toInt()
            if (unsigned < 16) "0${unsigned.toString(16)}" else unsigned.toString(16)
        }
        return "encrypted_data_$hexString"
    }

    private fun storeInKeychain(key: String, data: ByteArray): Boolean {
        val query = CFDictionaryCreateMutable(
            allocator = null,
            capacity = 0,
            keyCallBacks = null,
            valueCallBacks = null
        )

        val keyData = data.usePinned { pinned ->
            CFDataCreate(
                allocator = null,
                bytes = pinned.addressOf(0).reinterpret(),
                length = data.size.toLong()
            )
        }

        val keyString = CFStringCreateWithCString(
            alloc = null,
            cStr = key,
            encoding = kCFStringEncodingUTF8
        )
        val serviceString = CFStringCreateWithCString(
            alloc = null,
            cStr = SERVICE_NAME,
            encoding = kCFStringEncodingUTF8
        )

        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword)
        CFDictionarySetValue(query, kSecAttrAccount, keyString)
        CFDictionarySetValue(query, kSecAttrService, serviceString)
        CFDictionarySetValue(query, kSecValueData, keyData)
        CFDictionarySetValue(
            query,
            kSecAttrAccessible,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )

        // Remove existing item before adding new one
        SecItemDelete(query)

        val status = SecItemAdd(query, null)

        CFRelease(query)
        CFRelease(keyData)
        CFRelease(keyString)
        CFRelease(serviceString)

        return status == errSecSuccess
    }

    @Suppress("UNCHECKED_CAST")
    private fun retrieveFromKeychain(key: String): ByteArray? {
        val query = CFDictionaryCreateMutable(
            allocator = null,
            capacity = 0,
            keyCallBacks = null,
            valueCallBacks = null
        )

        val keyString = CFStringCreateWithCString(
            alloc = null,
            cStr = key,
            encoding = kCFStringEncodingUTF8
        )
        val serviceString = CFStringCreateWithCString(
            alloc = null,
            cStr = SERVICE_NAME,
            encoding = kCFStringEncodingUTF8
        )

        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword)
        CFDictionarySetValue(query, kSecAttrAccount, keyString)
        CFDictionarySetValue(query, kSecAttrService, serviceString)
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue)

        memScoped {
            val result = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, result.ptr)

            CFRelease(query)
            CFRelease(keyString)
            CFRelease(serviceString)

            if (status == errSecSuccess) {
                val data = result.value as CFDataRef
                val length = CFDataGetLength(data).toInt()
                val dataBytes = ByteArray(length)

                dataBytes.usePinned { pinned ->
                    CFDataGetBytes(
                        data,
                        CFRangeMake(0, length.toLong()),
                        pinned.addressOf(0).reinterpret()
                    )
                }

                CFRelease(data)
                return dataBytes
            }
        }

        return null
    }

    actual fun encrypt(bytes: ByteArray): ByteArray {
        val dataId = generateSecureId()
        val hasStored = storeInKeychain(dataId, bytes)

        if (!hasStored) {
            throw RuntimeException("Failed to store data in Keychain")
        }

        return dataId.encodeToByteArray()
    }

    actual fun decrypt(bytes: ByteArray): ByteArray {
        val dataId = bytes.decodeToString()

        return retrieveFromKeychain(dataId)
            ?: throw RuntimeException("Failed to retrieve data from Keychain")
    }
}