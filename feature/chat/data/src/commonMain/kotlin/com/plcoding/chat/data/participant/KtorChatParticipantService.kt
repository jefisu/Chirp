package com.plcoding.chat.data.participant

import com.plcoding.chat.data.dto.ChatParticipantDto
import com.plcoding.chat.data.dto.request.ConfirmProfilePictureRequest
import com.plcoding.chat.data.dto.response.ProfilePictureUploadUrlsResponse
import com.plcoding.chat.data.mappers.toChatParticipant
import com.plcoding.chat.data.mappers.toProfilePictureUploadUrls
import com.plcoding.chat.domain.models.ChatParticipant
import com.plcoding.chat.domain.models.ProfilePictureUploadUrls
import com.plcoding.chat.domain.participant.ChatParticipantService
import com.plcoding.core.data.networking.delete
import com.plcoding.core.data.networking.get
import com.plcoding.core.data.networking.post
import com.plcoding.core.data.networking.uploadToUrl
import com.plcoding.core.domain.util.DataError
import com.plcoding.core.domain.util.EmptyResult
import com.plcoding.core.domain.util.Result
import com.plcoding.core.domain.util.map
import io.ktor.client.HttpClient

class KtorChatParticipantService(
    private val httpClient: HttpClient
): ChatParticipantService {

    override suspend fun searchParticipant(query: String): Result<ChatParticipant, DataError.Remote> {
        return httpClient.get<ChatParticipantDto>(
            route = "/participants",
            queryParams = mapOf(
                "query" to query
            )
        ).map { it.toChatParticipant() }
    }

    override suspend fun getLocalParticipant(): Result<ChatParticipant, DataError.Remote> {
        return httpClient.get<ChatParticipantDto>(
            route = "/participants"
        ).map { it.toChatParticipant() }
    }

    override suspend fun getProfilePictureUploadUrl(mimeType: String): Result<ProfilePictureUploadUrls, DataError.Remote> {
        return httpClient.post<Unit, ProfilePictureUploadUrlsResponse>(
            route = "/participants/profile-picture-upload",
            queryParams = mapOf(
                "mimeType" to mimeType
            ),
            body = Unit
        ).map { it.toProfilePictureUploadUrls() }
    }

    override suspend fun uploadProfilePicture(
        uploadUrl: String,
        imageBytes: ByteArray,
        headers: Map<String, String>
    ): EmptyResult<DataError.Remote> {
        return httpClient.uploadToUrl(
            url = uploadUrl,
            body = imageBytes,
            headers = headers
        )
    }

    override suspend fun confirmProfilePictureUpload(publicUrl: String): EmptyResult<DataError.Remote> {
        return httpClient.post<ConfirmProfilePictureRequest, Unit>(
            route = "/participants/confirm-profile-picture",
            body = ConfirmProfilePictureRequest(publicUrl)
        )
    }

    override suspend fun deleteProfilePicture(): EmptyResult<DataError.Remote> {
        return httpClient.delete(
            route = "/participants/profile-picture"
        )
    }
}
