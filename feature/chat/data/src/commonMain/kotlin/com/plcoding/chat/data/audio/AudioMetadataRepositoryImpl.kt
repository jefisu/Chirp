package com.plcoding.chat.data.audio

import com.plcoding.chat.data.mappers.toDomain
import com.plcoding.chat.database.ChirpChatDatabase
import com.plcoding.chat.domain.audio.AudioMetadata
import com.plcoding.chat.domain.audio.AudioMetadataRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

class AudioMetadataRepositoryImpl(
    private val database: ChirpChatDatabase
) : AudioMetadataRepository {
    override fun getAllAudioMetadata(): Flow<List<AudioMetadata>> =
        database.audioMetadataDao.getAllAudioMetadata().map { entities ->
            entities.map { it.toDomain() }
        }
}
