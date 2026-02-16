package com.plcoding.chat.presentation.util

fun Long.formatDuration(): String {
    val totalSeconds = this / 1000
    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60
    return "${minutes.toString().padStart(1, '0')}:${seconds.toString().padStart(2, '0')}"
}
