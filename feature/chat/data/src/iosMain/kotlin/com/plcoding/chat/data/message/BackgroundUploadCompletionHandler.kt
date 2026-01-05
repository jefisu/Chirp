package com.plcoding.chat.data.message


object BackgroundUploadCompletionHandler {
    private var completionHandler: (() -> Unit)? = null

    fun setCompletionHandler(handler: () -> Unit) {
        completionHandler = handler
    }

    fun popCompletionHandler(): (() -> Unit)? {
        val handler = completionHandler
        completionHandler = null
        return handler
    }
}
