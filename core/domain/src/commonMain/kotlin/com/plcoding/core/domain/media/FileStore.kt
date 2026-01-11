package com.plcoding.core.domain.media

interface FileStore {
    suspend fun saveFile(
        bytes: ByteArray,
        fileName: String,
        destination: StorageDestination = StorageDestination.APP_STORAGE
    ): String?
    fun getFilePath(fileName: String): String
    suspend fun getFile(filePath: String): ByteArray?
    suspend fun deleteFile(filePath: String)
}

enum class StorageDestination {
    APP_STORAGE,
    GALLERY
}
