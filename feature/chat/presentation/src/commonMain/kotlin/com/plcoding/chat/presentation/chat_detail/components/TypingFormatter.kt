package com.plcoding.chat.presentation.chat_detail.components

import chirp.feature.chat.presentation.generated.resources.Res
import chirp.feature.chat.presentation.generated.resources.are_typing
import chirp.feature.chat.presentation.generated.resources.is_typing
import chirp.feature.chat.presentation.generated.resources.several_people_are_typing
import com.plcoding.core.presentation.util.UiText

object TypingFormatter {
    fun format(typingUsers: List<String>): UiText? {
        return when {
            typingUsers.isEmpty() -> null
            typingUsers.size == 1 -> UiText.Resource(Res.string.is_typing, arrayOf(typingUsers[0]))
            typingUsers.size in 2..3 -> UiText.Resource(
                Res.string.are_typing,
                arrayOf(typingUsers.joinToString(", "))
            )

            else -> UiText.Resource(Res.string.several_people_are_typing)
        }
    }
}
