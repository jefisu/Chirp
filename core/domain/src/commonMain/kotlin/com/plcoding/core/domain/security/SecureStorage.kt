package com.plcoding.core.domain.security

interface SecureStorage {
    suspend fun saveString(key: String, value: String)
    suspend fun getString(key: String): String?
    suspend fun remove(key: String)
    suspend fun clear()
}
