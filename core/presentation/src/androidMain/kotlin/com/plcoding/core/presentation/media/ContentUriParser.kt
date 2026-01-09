package com.plcoding.core.presentation.media

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

class ContentUriParser(
    private val context: Context
) {
    suspend fun readUri(uri: Uri): ByteArray? {
        return withContext(Dispatchers.IO) {
            val options = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                BitmapFactory.decodeStream(inputStream, null, options)
            }

            val width = options.outWidth
            val height = options.outHeight

            if (width == -1 || height == -1) {
                // Fallback for non-image files or failure to decode bounds
                return@withContext context.contentResolver.openInputStream(uri)
                    ?.use { inputStream ->
                        inputStream.readBytes()
                    }
            }

            val maxDimension = 2500
            var inSampleSize = 1

            if (width > maxDimension || height > maxDimension) {
                val halfHeight = height / 2
                val halfWidth = width / 2
                while ((halfHeight / inSampleSize) >= maxDimension && (halfWidth / inSampleSize) >= maxDimension) {
                    inSampleSize *= 2
                }
            }

            if (inSampleSize > 1) {
                // Downsample image
                val decodeOptions = BitmapFactory.Options().apply {
                    this.inSampleSize = inSampleSize
                }

                val bitmap = context.contentResolver.openInputStream(uri)?.use { inputStream ->
                    BitmapFactory.decodeStream(inputStream, null, decodeOptions)
                } ?: return@withContext null

                val outputStream = ByteArrayOutputStream()
                bitmap.compress(Bitmap.CompressFormat.JPEG, 90, outputStream)
                bitmap.recycle()

                return@withContext outputStream.toByteArray()
            }

            // If image is small enough, read original bytes
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

    suspend fun getDimensions(uri: Uri): Pair<Int, Int> {
        return withContext(Dispatchers.IO) {
            val options = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                BitmapFactory.decodeStream(inputStream, null, options)
            }
            options.outWidth to options.outHeight
        }
    }
}
