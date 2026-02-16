package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.AttachmentUploadInfoDto
import com.plcoding.chat.data.dto.request.AttachmentUploadRequest
import com.plcoding.chat.domain.models.AttachmentUploadInfo
import com.plcoding.core.domain.media.File
import kotlin.time.Instant

fun File.toAttachmentUploadRequest(): AttachmentUploadRequest {
    val destination = when {
        mimeType?.startsWith("image") == true -> "images"
        mimeType?.startsWith("audio") == true -> "audios"
        else -> error("Unsupported mime type: $mimeType")
    }
    return AttachmentUploadRequest(
        fileName = name,
        mimeType = mimeType ?: error("MimeType unknown"),
        destination = destination
    )
}

fun AttachmentUploadInfoDto.toAttachmentUploadInfo(file: File): AttachmentUploadInfo {
    return AttachmentUploadInfo(
        originalFile = file,
        uploadUrl = uploadUrl,
        expiresAt = Instant.parse(expiresAt),
        publicUrl = publicUrl,
    )
}
