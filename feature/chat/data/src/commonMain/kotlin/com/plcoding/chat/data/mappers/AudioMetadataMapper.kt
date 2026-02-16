package com.plcoding.chat.data.mappers

import com.plcoding.chat.database.entities.AudioMetadataEntity
import com.plcoding.chat.domain.audio.AudioMetadata

fun AudioMetadataEntity.toDomain(): AudioMetadata =
    AudioMetadata(
        attachmentId = attachmentId,
        durationMs = durationMs,
        amplitudes = if (amplitudes.isNotEmpty()) {
            amplitudes.split(",").mapNotNull { it.toFloatOrNull() }
        } else {
            emptyList()
        },
    )

fun AudioMetadata.toEntity(): AudioMetadataEntity =
    AudioMetadataEntity(
        attachmentId = attachmentId,
        durationMs = durationMs,
        amplitudes = amplitudes.joinToString(","),
    )
