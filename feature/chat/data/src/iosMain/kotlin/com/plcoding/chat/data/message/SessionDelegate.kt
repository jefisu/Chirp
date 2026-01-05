package com.plcoding.chat.data.message

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import platform.Foundation.NSError
import platform.Foundation.NSURLSession
import platform.Foundation.NSURLSessionTask
import platform.Foundation.NSURLSessionTaskDelegateProtocol
import platform.darwin.NSObject

class SessionDelegate(
    private val registry: MutableMap<String, CallbackPair>,
    private val applicationScope: CoroutineScope
) : NSObject(), NSURLSessionTaskDelegateProtocol {

    @Suppress("CONFLICTING_OVERLOADS")
    override fun URLSession(
        session: NSURLSession,
        task: NSURLSessionTask,
        didCompleteWithError: NSError?
    ) {
        val attachmentId = task.taskDescription ?: return
        val callbacks = registry[attachmentId] ?: return

        registry.remove(attachmentId)

        if (didCompleteWithError != null) {
            applicationScope.launch(Dispatchers.IO) {
                callbacks.onFailure()
            }
            return
        }

        applicationScope.launch(Dispatchers.IO) {
            callbacks.onSuccess()
        }
    }
}

data class CallbackPair(
    val onSuccess: suspend () -> Unit,
    val onFailure: suspend () -> Unit
)
