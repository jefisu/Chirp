package com.plcoding.core.data.media

import com.plcoding.core.domain.media.FileStore
import com.plcoding.core.domain.media.StorageDestination
import java.io.File

actual class NativeFileStore(
    private val fileStore: JvmFileStore
) : FileStore {

    actual override suspend fun saveFile(
        bytes: ByteArray,
        fileName: String,
        destination: StorageDestination
    ): String? {
        val directory = when (destination) {
            StorageDestination.APP_STORAGE -> File(System.getProperty("java.io.tmpdir"))
            StorageDestination.GALLERY -> File(System.getProperty("user.home"), "Downloads")
        }
        return fileStore.saveFile(bytes, directory, fileName)
    }

    actual override fun getFilePath(fileName: String): String {
        val tempDir = File(System.getProperty("java.io.tmpdir"))
        return File(tempDir, fileName).absolutePath
    }

    actual override suspend fun getFile(filePath: String): ByteArray? {
        return fileStore.getFile(filePath)
    }

    actual override suspend fun deleteFile(filePath: String) {
        fileStore.deleteFile(filePath)
    }
}
