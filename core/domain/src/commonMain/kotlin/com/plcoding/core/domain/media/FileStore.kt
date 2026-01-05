package com.plcoding.core.domain.media

interface FileStore {
    suspend fun saveFile(bytes: ByteArray, fileName: String): String?
    fun getFilePath(fileName: String): String
    suspend fun getFile(filePath: String): ByteArray?
    suspend fun deleteFile(filePath: String)
}
