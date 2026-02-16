package com.plcoding.chat.domain.audio

import kotlinx.coroutines.flow.Flow

interface AudioMetadataRepository {
    fun getAllAudioMetadata(): Flow<List<AudioMetadata>>
}
