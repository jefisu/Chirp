package com.plcoding.core.data.security

import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.security.SecureStorage

actual class NativeSecureStorage(
    private val logger: ChirpLogger
) : SecureStorage {

    private val delegate: SecureStorage by lazy {
        when {
            isWindows -> WindowsSecureStorage(logger)
            isMacOs -> MacOsSecureStorage(logger)
            isLinux -> LinuxSecureStorage(logger)
            else -> throw UnsupportedOperationException("Unsupported operating system")
        }
    }

    actual override suspend fun saveString(key: String, value: String) {
        delegate.saveString(key, value)
    }

    actual override suspend fun getString(key: String): String? {
        return delegate.getString(key)
    }

    actual override suspend fun remove(key: String) {
        delegate.remove(key)
    }

    actual override suspend fun clear() {
        delegate.clear()
    }

    companion object {
        private val osName = System.getProperty("os.name").lowercase()
        private val isWindows = osName.contains("win")
        private val isMacOs = osName.contains("mac")
        private val isLinux = osName.contains("nux") || osName.contains("nix")
    }
}
