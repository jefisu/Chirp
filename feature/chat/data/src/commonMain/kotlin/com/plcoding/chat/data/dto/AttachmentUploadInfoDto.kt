package com.plcoding.chat.data.dto

import kotlinx.serialization.Serializable

@Serializable
data class AttachmentUploadInfoDto(
    val fileName: String,
    val uploadUrl: String,
    val expiresAt: String,
    val publicUrl: String,
)
