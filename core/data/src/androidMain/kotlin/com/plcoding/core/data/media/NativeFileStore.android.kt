package com.plcoding.core.data.media

import android.content.ContentValues
import android.content.Context
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import androidx.annotation.RequiresApi
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.media.FileStore
import com.plcoding.core.domain.media.StorageDestination
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

actual class NativeFileStore(
    private val context: Context,
    private val fileStore: JvmFileStore,
    private val logger: ChirpLogger
) : FileStore {

    actual override suspend fun saveFile(
        bytes: ByteArray,
        fileName: String,
        destination: StorageDestination
    ): String? = withContext(Dispatchers.IO) {
        when (destination) {
            StorageDestination.APP_STORAGE -> {
                fileStore.saveFile(bytes, context.filesDir, fileName)
            }

            StorageDestination.GALLERY -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    saveModern(bytes, fileName)
                } else {
                    saveLegacy(bytes, fileName)
                }
            }
        }
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

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun saveModern(
        bytes: ByteArray,
        fileName: String,
    ): String? {
        val mimeType = getMimeType(fileName)
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
        val relativePath = Environment.DIRECTORY_DOWNLOADS

        val contentValues = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
            put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }

        val uri = context.contentResolver.insert(collection, contentValues) ?: return null

        return try {
            context.contentResolver.openOutputStream(uri)?.use {
                it.write(bytes)
            }

            contentValues.clear()
            contentValues.put(MediaStore.MediaColumns.IS_PENDING, 0)
            context.contentResolver.update(uri, contentValues, null, null)

            uri.toString()
        } catch (e: Exception) {
            context.contentResolver.delete(uri, null, null)
            logger.error("Failed to write to MediaStore: $fileName", e)
            null
        }
    }

    private suspend fun saveLegacy(
        bytes: ByteArray,
        fileName: String,
    ): String? {
        val directory =
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        return fileStore.saveFile(bytes, directory, fileName)?.also { path ->
            MediaScannerConnection.scanFile(context, arrayOf(path), null, null)
        }
    }

    private fun getMimeType(fileName: String): String {
        val extension = fileName.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension) ?: "*/*"
    }
}
