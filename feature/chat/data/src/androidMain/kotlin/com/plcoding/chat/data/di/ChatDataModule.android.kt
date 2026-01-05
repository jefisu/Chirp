package com.plcoding.chat.data.di

import androidx.work.WorkManager
import com.plcoding.chat.data.lifecycle.AppLifecycleObserver
import com.plcoding.chat.data.message.MessageAttachmentUploadWorker
import com.plcoding.chat.data.message.NativeMessageAttachmentScheduler
import com.plcoding.chat.data.message.UploaderMessageAttachmentService
import com.plcoding.chat.data.network.ConnectionErrorHandler
import com.plcoding.chat.data.network.ConnectivityObserver
import com.plcoding.chat.data.notification.FirebasePushNotificationService
import com.plcoding.chat.database.DatabaseFactory
import com.plcoding.chat.domain.message.MessageAttachmentScheduler
import com.plcoding.chat.domain.notification.PushNotificationService
import org.koin.android.ext.koin.androidContext
import org.koin.androidx.workmanager.dsl.workerOf
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.bind
import org.koin.dsl.module

actual val platformChatDataModule = module {
    single { DatabaseFactory(androidContext()) }
    singleOf(::AppLifecycleObserver)
    singleOf(::ConnectivityObserver)
    singleOf(::ConnectionErrorHandler)

    singleOf(::FirebasePushNotificationService) bind PushNotificationService::class
    single { WorkManager.getInstance(androidContext()) }
    workerOf(::MessageAttachmentUploadWorker)
    singleOf(::NativeMessageAttachmentScheduler).bind<MessageAttachmentScheduler>()
    singleOf(::UploaderMessageAttachmentService)
}
