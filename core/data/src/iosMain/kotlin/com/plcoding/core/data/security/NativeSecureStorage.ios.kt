@file:OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)

package com.plcoding.core.data.security

import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.security.SecureStorage
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnData
import platform.Security.kSecValueData

actual class NativeSecureStorage(
    private val logger: ChirpLogger
) : SecureStorage {

    private val serviceName = "com.plcoding.chirp"

    actual override suspend fun saveString(key: String, value: String) {
        try {
            val data = (value as NSString).dataUsingEncoding(NSUTF8StringEncoding) ?: run {
                logger.error("Failed to encode string for key: $key")
                return
            }

            deleteItem(key)

            val query = createMutableDictionary()
            CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionaryAddValue(query, kSecAttrService, CFBridgingRetain(serviceName))
            CFDictionaryAddValue(query, kSecAttrAccount, CFBridgingRetain(key))
            CFDictionaryAddValue(query, kSecValueData, CFBridgingRetain(data))

            val status = SecItemAdd(query as CFDictionaryRef, null)
            CFRelease(query)

            if (status != errSecSuccess) {
                logger.error("Failed to save to Keychain for key: $key, status: $status")
            }
        } catch (e: Exception) {
            logger.error("Failed to save encrypted data for key: $key", e)
        }
    }

    actual override suspend fun getString(key: String): String? {
        return try {
            val query = createMutableDictionary()
            CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionaryAddValue(query, kSecAttrService, CFBridgingRetain(serviceName))
            CFDictionaryAddValue(query, kSecAttrAccount, CFBridgingRetain(key))
            CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue)
            CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne)

            memScoped {
                val result = alloc<CFTypeRefVar>()
                val status = SecItemCopyMatching(query as CFDictionaryRef, result.ptr)
                CFRelease(query)

                when (status) {
                    errSecSuccess -> {
                        val data = CFBridgingRelease(result.value) as? NSData
                        data?.let {
                            NSString.create(data = it, encoding = NSUTF8StringEncoding) as? String
                        }
                    }
                    ERR_SEC_ITEM_NOT_FOUND -> null
                    else -> {
                        logger.warn("Failed to retrieve from Keychain for key: $key, status: $status")
                        null
                    }
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to retrieve encrypted data for key: $key", e)
            null
        }
    }

    actual override suspend fun remove(key: String) {
        try {
            deleteItem(key)
        } catch (e: Exception) {
            logger.error("Failed to remove data for key: $key", e)
        }
    }

    actual override suspend fun clear() {
        try {
            val query = createMutableDictionary()
            CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionaryAddValue(query, kSecAttrService, CFBridgingRetain(serviceName))

            val status = SecItemDelete(query as CFDictionaryRef)
            CFRelease(query)

            if (status != errSecSuccess && status != ERR_SEC_ITEM_NOT_FOUND) {
                logger.error("Failed to clear Keychain, status: $status")
            }
        } catch (e: Exception) {
            logger.error("Failed to clear secure storage", e)
        }
    }

    private fun deleteItem(key: String) {
        val query = createMutableDictionary()
        CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
        CFDictionaryAddValue(query, kSecAttrService, CFBridgingRetain(serviceName))
        CFDictionaryAddValue(query, kSecAttrAccount, CFBridgingRetain(key))

        SecItemDelete(query as CFDictionaryRef)
        CFRelease(query)
    }

    private fun createMutableDictionary() = CFDictionaryCreateMutable(null, 0, null, null)

    private companion object {
        const val ERR_SEC_ITEM_NOT_FOUND = -25300
    }
}
