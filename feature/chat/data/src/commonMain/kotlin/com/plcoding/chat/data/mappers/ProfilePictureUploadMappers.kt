package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.response.ProfilePictureUploadUrlsResponse
import com.plcoding.chat.domain.models.ProfilePictureUploadUrls

fun ProfilePictureUploadUrlsResponse.toProfilePictureUploadUrls(): ProfilePictureUploadUrls {
    return ProfilePictureUploadUrls(
        uploadUrl = uploadUrl,
        publicUrl = publicUrl,
        headers = headers
    )
}