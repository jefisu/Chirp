package com.plcoding.core.data.security

import com.plcoding.core.domain.security.SecureStorage

expect class NativeSecureStorage : SecureStorage {
    override suspend fun saveString(key: String, value: String)
    override suspend fun getString(key: String): String?
    override suspend fun remove(key: String)
    override suspend fun clear()
}
