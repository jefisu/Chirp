package com.plcoding.chat.database.dao

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert
import com.plcoding.chat.database.entities.AudioMetadataEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface AudioMetadataDao {
    @Upsert
    suspend fun upsert(metadata: AudioMetadataEntity)

    @Upsert
    suspend fun upsertAll(metadata: List<AudioMetadataEntity>)

    @Query("SELECT * FROM audiometadataentity")
    fun getAllAudioMetadata(): Flow<List<AudioMetadataEntity>>

    @Query("SELECT * FROM audiometadataentity WHERE attachmentId IN (SELECT id FROM messageattachmententity WHERE messageId = :messageId)")
    suspend fun getAudioMetadataByMessageId(messageId: String): List<AudioMetadataEntity>

    @Query("DELETE FROM audiometadataentity WHERE attachmentId IN (:attachmentIds)")
    suspend fun deleteAudioMetadata(attachmentIds: List<String>)

    @Transaction
    suspend fun upsertAudioMetadataAndSync(
        messageId: String,
        serverAudioMetadata: List<AudioMetadataEntity>,
    ) {
        val existingMetadata = getAudioMetadataByMessageId(messageId)
        val serverIds = serverAudioMetadata.map { it.attachmentId }.toSet()

        upsertAll(serverAudioMetadata)

        val metadataToDelete = existingMetadata.filter {
            it.attachmentId !in serverIds
        }
        if (metadataToDelete.isNotEmpty()) {
            deleteAudioMetadata(metadataToDelete.map { it.attachmentId })
        }
    }
}
