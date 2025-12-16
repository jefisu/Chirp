package com.plcoding.core.presentation.media

import android.content.Context
import android.net.Uri
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ContentUriParser(
    private val context: Context
) {
    suspend fun readUri(uri: Uri): ByteArray? {
        return withContext(Dispatchers.IO) {
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                inputStream.readBytes()
            }
        }
    }


    suspend fun getFileName(uri: Uri): String? {
        return withContext(Dispatchers.IO) {
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val columnIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
                    cursor.getString(columnIndex)
                } else null
            }
        }
    }

    fun getMimeType(uri: Uri): String? {
        return context.contentResolver.getType(uri)
            ?: getMimeTypeFromExtension(uri)
    }

    private fun getMimeTypeFromExtension(uri: Uri): String? {
        val extension = uri.toString().substringAfterLast(".", "")
        return if (extension.isNotBlank()) {
            MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
        } else null
    }
}