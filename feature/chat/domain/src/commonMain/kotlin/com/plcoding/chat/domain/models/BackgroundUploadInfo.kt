package com.plcoding.chat.domain.models

data class BackgroundUploadInfo(
    val fileId: String,
    val uploadUrl: String,
    val localFilePath: String
)
