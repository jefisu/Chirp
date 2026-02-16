package com.plcoding.chat.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class AudioMetadataEntity(
    @PrimaryKey
    val attachmentId: String,
    val durationMs: Long,
    val amplitudes: String,
)
