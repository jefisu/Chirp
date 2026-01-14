package com.plcoding.chat.data.mappers

import com.plcoding.chat.data.dto.websocket.OutgoingWebSocketDto
import com.plcoding.chat.data.dto.websocket.WebSocketMessageDto
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

fun Json.wrapOutgoingMessage(dto: OutgoingWebSocketDto): String {
    val payloadElement = when (dto) {
        is OutgoingWebSocketDto.NewMessage -> encodeToJsonElement(dto)
        is OutgoingWebSocketDto.TypingEvent -> encodeToJsonElement(dto)
    }

    val payloadMap = payloadElement.jsonObject.toMutableMap().apply {
        remove("type")
    }

    val webSocketMessage = WebSocketMessageDto(
        type = dto.type.name,
        payload = encodeToString(JsonObject(payloadMap))
    )

    return encodeToString(webSocketMessage)
}

