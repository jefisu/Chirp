package com.plcoding.chat.data.message

import com.plcoding.chat.data.dto.AttachmentUploadInfoDto
import com.plcoding.chat.data.dto.request.AttachmentUploadRequest
import com.plcoding.chat.data.mappers.toAttachmentUploadInfo
import com.plcoding.chat.data.mappers.toAttachmentUploadRequest
import com.plcoding.chat.domain.message.MessageAttachmentService
import com.plcoding.chat.domain.models.AttachmentUploadInfo
import com.plcoding.core.data.networking.get
import com.plcoding.core.data.networking.post
import com.plcoding.core.domain.logging.ChirpLogger
import com.plcoding.core.domain.media.File
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.Result
import com.plcoding.core.domain.util.map
import io.ktor.client.HttpClient

class KtorMessageAttachmentService(
    private val httpClient: HttpClient,
    private val uploaderMessageAttachmentService: UploaderMessageAttachmentService,
    private val logger: ChirpLogger
) : MessageAttachmentService {

    override suspend fun getUploadFilesUrl(
        chatId: String,
        files: List<File>
    ): Result<List<AttachmentUploadInfo>, DataError.Remote> {
        return httpClient
            .post<List<AttachmentUploadRequest>, List<AttachmentUploadInfoDto>>(
                route = "chat/$chatId/files-upload",
                body = files.map { it.toAttachmentUploadRequest() }
            )
            .map { response ->
                response.map { dto ->
                    val file = files.first { it.name == dto.fileName }
                    dto.toAttachmentUploadInfo(file)
                }
            }
    }

    override suspend fun uploadFile(
        attachmentId: String,
        uploadUrl: String,
        binaryData: ByteArray,
        headers: Map<String, String>,
        onSuccess: suspend () -> Unit,
        onFailure: suspend () -> Unit
    ) {
        uploaderMessageAttachmentService.uploadFile(
            attachmentId = attachmentId,
            uploadUrl = uploadUrl,
            binaryData = binaryData,
            headers = headers,
            onSuccess = onSuccess,
            onFailure = onFailure
        )
    }

    override suspend fun downloadAttachment(url: String): Result<ByteArray, DataError.Remote> {
        return httpClient.get<ByteArray>(
            route = url,
            useBaseUrl = false
        )
    }
}
