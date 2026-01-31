package com.plcoding.chat.database.dao

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Upsert
import com.plcoding.chat.database.entities.ChatEventEntity
import com.plcoding.chat.database.entities.ChatEventWithUsers
import kotlinx.coroutines.flow.Flow

@Dao
interface ChatEventDao {

    @Upsert
    suspend fun upsertEvent(event: ChatEventEntity)

    @Upsert
    suspend fun upsertEvents(events: List<ChatEventEntity>)

    @Transaction
    @Query("SELECT * FROM chatevententity WHERE chatId = :chatId ORDER BY timestamp DESC")
    fun getEventsWithUsersByChatId(chatId: String): Flow<List<ChatEventWithUsers>>

    @Transaction
    @Query("SELECT * FROM chatevententity WHERE eventId = :eventId")
    suspend fun getEventWithUsersById(eventId: String): ChatEventWithUsers?
}
