package com.plcoding.chirp

import android.app.Application
import androidx.work.Configuration
import com.plcoding.chirp.di.initKoin
import org.koin.android.ext.koin.androidContext
import org.koin.android.ext.koin.androidLogger
import org.koin.androidx.workmanager.factory.KoinWorkerFactory
import org.koin.androidx.workmanager.koin.workManagerFactory

class ChirpApplication: Application(), Configuration.Provider {

    override fun onCreate() {
        super.onCreate()
        initKoin {
            androidContext(this@ChirpApplication)
            androidLogger()
            workManagerFactory()
        }
    }

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(KoinWorkerFactory())
            .build()
}
