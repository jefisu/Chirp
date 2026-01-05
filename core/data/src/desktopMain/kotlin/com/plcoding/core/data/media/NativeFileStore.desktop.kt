package com.plcoding.core.data.media

import com.plcoding.core.domain.media.FileStore
import java.io.File

actual class NativeFileStore(
    private val fileStore: JvmFileStore
) : FileStore {

    actual override suspend fun saveFile(bytes: ByteArray, fileName: String): String? {
        val tempDir = File(System.getProperty("java.io.tmpdir"))
        return fileStore.saveFile(bytes, tempDir, fileName)
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
