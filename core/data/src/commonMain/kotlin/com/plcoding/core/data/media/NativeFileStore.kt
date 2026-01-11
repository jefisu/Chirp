package com.plcoding.core.data.media

import com.plcoding.core.domain.media.FileStore
import com.plcoding.core.domain.media.StorageDestination

expect class NativeFileStore: FileStore {
    override suspend fun saveFile(
        bytes: ByteArray,
        fileName: String,
        destination: StorageDestination
    ): String?
    override fun getFilePath(fileName: String): String
    override suspend fun getFile(filePath: String): ByteArray?
    override suspend fun deleteFile(filePath: String)
}