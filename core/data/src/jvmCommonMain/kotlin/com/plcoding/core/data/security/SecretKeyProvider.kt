package com.plcoding.core.data.security

import javax.crypto.SecretKey

expect object SecretKeyProvider {
    fun getKey(): SecretKey
}