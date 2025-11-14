@file:OptIn(ExperimentalEncodingApi::class)

package com.plcoding.core.data.preferences

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.plcoding.core.data.security.Crypto
import com.plcoding.core.data.security.decryptFromBase64
import com.plcoding.core.data.security.encryptToBase64
import com.plcoding.core.domain.preferences.ThemePreference
import com.plcoding.core.domain.preferences.ThemePreferences
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlin.io.encoding.ExperimentalEncodingApi

class DataStoreThemePreferences(
    private val dataStore: DataStore<Preferences>
) : ThemePreferences {

    private val themePreferenceKey = stringPreferencesKey("theme_preference")

    override fun observeThemePreference(): Flow<ThemePreference> {
        return dataStore
            .data
            .map { preferences ->
                val encryptedBase64 = preferences[themePreferenceKey]
                    ?: return@map ThemePreference.SYSTEM
                val themeBytes = Crypto.decryptFromBase64(encryptedBase64)
                try {
                    ThemePreference.valueOf(themeBytes.decodeToString())
                } catch (_: Exception) {
                    ThemePreference.SYSTEM
                }
            }
    }

    override suspend fun updateThemePreference(theme: ThemePreference) {
        val themeBytes = theme.name.encodeToByteArray()
        dataStore.edit { preferences ->
            preferences[themePreferenceKey] = Crypto.encryptToBase64(themeBytes)
        }
    }
}