package com.plcoding.chat.data.dto.request

import kotlinx.serialization.Serializable

@Serializable
data class AttachmentUploadRequest(
    val fileName: String,
    val mimeType: String
)
