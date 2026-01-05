package com.plcoding.chat.data.message

import kotlinx.coroutines.CoroutineScope
import platform.Foundation.NSMutableURLRequest
import platform.Foundation.NSURL
import platform.Foundation.NSURLSession
import platform.Foundation.NSURLSessionConfiguration
import platform.Foundation.NSURLSessionTask
import platform.Foundation.setHTTPMethod
import platform.Foundation.setValue

class IosBackgroundUploadManager(
    private val applicationScope: CoroutineScope
) {
    private val registry = mutableMapOf<String, CallbackPair>()
    private val delegate = SessionDelegate(registry, applicationScope)

    private val session: NSURLSession by lazy {
        val config = NSURLSessionConfiguration.backgroundSessionConfigurationWithIdentifier(
            identifier = "com.plcoding.chirp.background_upload"
        )
        NSURLSession.sessionWithConfiguration(
            configuration = config,
            delegate = delegate,
            delegateQueue = null
        )
    }

    fun scheduleTask(
        attachmentId: String,
        filePath: String,
        uploadUrl: String,
        headers: Map<String, String>,
        onSuccess: suspend () -> Unit,
        onFailure: suspend () -> Unit
    ) {
        val url = NSURL.URLWithString(uploadUrl) ?: return

        val request = NSMutableURLRequest
            .requestWithURL(url)
            .apply {
                setHTTPMethod("PUT")
                headers.forEach { (key, value) ->
                    setValue(value, forHTTPHeaderField = key)
                }
            }

        val fileUrl = NSURL.fileURLWithPath(filePath)
        val task = session.uploadTaskWithRequest(request, fromFile = fileUrl)

        task.setTaskDescription(attachmentId)

        registry[attachmentId] = CallbackPair(onSuccess, onFailure)

        task.resume()
    }

    fun cancelTask(attachmentId: String) {
        session.getTasksWithCompletionHandler { _, uploadTasks, _ ->
            val tasks = uploadTasks
                ?.filterIsInstance<NSURLSessionTask>()
                ?: return@getTasksWithCompletionHandler
            tasks.find { it.taskDescription == attachmentId }?.cancel()
            registry.remove(attachmentId)
        }
    }
}
