@file:OptIn(ExperimentalEncodingApi::class)

package com.plcoding.core.data.auth

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.plcoding.core.data.dto.AuthInfoSerializable
import com.plcoding.core.data.mappers.toDomain
import com.plcoding.core.data.mappers.toSerializable
import com.plcoding.core.data.security.Crypto
import com.plcoding.core.data.security.decryptFromBase64
import com.plcoding.core.data.security.encryptToBase64
import com.plcoding.core.domain.auth.AuthInfo
import com.plcoding.core.domain.auth.SessionStorage
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.Json
import kotlin.io.encoding.ExperimentalEncodingApi

class DataStoreSessionStorage(
    private val dataStore: DataStore<Preferences>
) : SessionStorage {

    private val authInfoKey = stringPreferencesKey("KEY_AUTH_INFO")

    private val json = Json {
        ignoreUnknownKeys = true
    }

    override fun observeAuthInfo(): Flow<AuthInfo?> {
        return dataStore.data.map { preferences ->
            val encryptedBase64 = preferences[authInfoKey]
            encryptedBase64?.let {
                val serialized = Crypto.decryptFromBase64(it).decodeToString()
                json.decodeFromString<AuthInfoSerializable>(serialized).toDomain()
            }
        }
    }

    override suspend fun set(info: AuthInfo?) {
        if (info == null) {
            dataStore.edit {
                it.remove(authInfoKey)
            }
            return
        }

        val serialized = json.encodeToString(info.toSerializable())
        dataStore.edit { prefs ->
            prefs[authInfoKey] = Crypto.encryptToBase64(serialized.encodeToByteArray())
        }
    }
}