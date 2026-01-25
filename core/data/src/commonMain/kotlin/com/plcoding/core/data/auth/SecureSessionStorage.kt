package com.plcoding.core.data.auth

import com.plcoding.core.data.dto.AuthInfoSerializable
import com.plcoding.core.data.mappers.toDomain
import com.plcoding.core.data.mappers.toSerializable
import com.plcoding.core.domain.auth.AuthInfo
import com.plcoding.core.domain.auth.SessionStorage
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.security.SecureStorage
import com.plcoding.core.domain.security.SecureStorageKeys
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.onStart
import kotlinx.serialization.json.Json

class SecureSessionStorage(
    private val secureStorage: SecureStorage,
    private val logger: ChirpLogger
) : SessionStorage {

    private val json = Json {
        ignoreUnknownKeys = true
    }

    private val authInfoFlow = MutableStateFlow<AuthInfo?>(null)
    private var isInitialized = false

    override fun observeAuthInfo(): Flow<AuthInfo?> {
        return authInfoFlow.onStart {
            if (!isInitialized) {
                loadAuthInfo()
                isInitialized = true
            }
        }
    }

    override suspend fun set(info: AuthInfo?) {
        if (info == null) {
            secureStorage.remove(SecureStorageKeys.AUTH_INFO)
            authInfoFlow.value = null
            return
        }

        val serialized = json.encodeToString(info.toSerializable())
        secureStorage.saveString(SecureStorageKeys.AUTH_INFO, serialized)
        authInfoFlow.value = info
    }

    private suspend fun loadAuthInfo() {
        val serializedJson = secureStorage.getString(SecureStorageKeys.AUTH_INFO)

        if (serializedJson == null) {
            logger.debug("SecureSessionStorage: No auth info found in secure storage")
            authInfoFlow.value = null
            return
        }

        authInfoFlow.value = runCatching {
            json.decodeFromString<AuthInfoSerializable>(serializedJson).toDomain()
        }.onFailure { error ->
            logger.error("SecureSessionStorage: Failed to deserialize auth info", error)
        }.getOrNull()
    }
}
