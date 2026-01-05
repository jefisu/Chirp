package com.plcoding.chirp

import com.plcoding.chat.data.message.BackgroundUploadCompletionHandler

object IosBackgroundUploadBridge {
    fun setCompletionHandler(handler: () -> Unit) {
        BackgroundUploadCompletionHandler.setCompletionHandler(handler)
    }

    fun popCompletionHandler(): (() -> Unit)? {
        return BackgroundUploadCompletionHandler.popCompletionHandler()
    }
}