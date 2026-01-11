package com.plcoding.chat.data.message

import com.plcoding.chat.domain.message.MessageAttachmentService
import com.plcoding.chat.domain.models.AttachmentUploadInfo
import com.plcoding.core.data.networking.uploadToUrl
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.Result
import com.plcoding.core.domain.util.onFailure
import com.plcoding.core.domain.util.onSuccess
import io.ktor.client.HttpClient

actual class UploaderMessageAttachmentService(
    private val httpClient: HttpClient
) : MessageAttachmentService {

    actual override suspend fun getUploadFilesUrl(
        chatId: String,
        files: List<File>
    ): Result<List<AttachmentUploadInfo>, DataError.Remote> {
        TODO("Not implemented")
    }

    actual override suspend fun uploadFile(
        attachmentId: String,
        uploadUrl: String,
        binaryData: ByteArray,
        headers: Map<String, String>,
        onSuccess: suspend () -> Unit,
        onFailure: suspend () -> Unit
    ) {
        httpClient.uploadToUrl(
            url = uploadUrl,
            body = binaryData,
            headers = headers
        ).onSuccess {
            onSuccess()
        }.onFailure {
            onFailure()
        }
    }

    actual override suspend fun downloadAttachment(url: String): Result<ByteArray, DataError.Remote> {
        TODO("Not implemented")
    }
}