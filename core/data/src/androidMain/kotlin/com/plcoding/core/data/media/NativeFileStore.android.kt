package com.plcoding.core.data.media

import android.content.Context
import com.plcoding.core.domain.media.FileStore
import java.io.File

actual class NativeFileStore(
    private val context: Context,
    private val fileStore: JvmFileStore
): FileStore {

    actual override suspend fun saveFile(bytes: ByteArray, fileName: String): String? {
        return fileStore.saveFile(bytes, context.filesDir, fileName)
    }

    actual override fun getFilePath(fileName: String): String {
        return File(context.filesDir, fileName).absolutePath
    }

    actual override suspend fun getFile(filePath: String): ByteArray? {
        return fileStore.getFile(filePath)
    }

    actual override suspend fun deleteFile(filePath: String) {
        fileStore.deleteFile(filePath)
    }
}
