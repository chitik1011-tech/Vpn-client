package dev.aurora.vpn.data

import android.content.Context
import dev.aurora.vpn.core.ServerProfile
import dev.aurora.vpn.core.VlessParser
import dev.aurora.vpn.subscriptions.SubscriptionImporter
import dev.aurora.vpn.subscriptions.HappAdd
import dev.aurora.vpn.subscriptions.ProxyLinkParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

class ProfileRepository(context: Context) {
    private val store = SecretStore(context.applicationContext)
    private val importer = SubscriptionImporter()
    private val state = MutableStateFlow(store.read())
    val profiles = state.asStateFlow()

    suspend fun addLink(text: String) = withContext(Dispatchers.IO) {
        val trimmed = text.trim()
        val imported = when {
            ProxyLinkParser.isShareLink(trimmed) -> listOf(ProxyLinkParser.parse(trimmed))
            trimmed.startsWith("https://", true) -> importer.download(trimmed)
            trimmed.startsWith("happ://add/", true) -> importer.download(HappAdd.resolve(trimmed))
            trimmed.startsWith("happ://", true) -> error(
                "Encrypted/opaque Happ links require a provider-supported import API; use an authorized HTTPS URL"
            )
            else -> importer.parseContent(trimmed)
        }
        val merged = (state.value + imported).distinctBy { it.id }
        store.write(merged)
        state.value = merged
    }

    suspend fun remove(profile: ServerProfile) = withContext(Dispatchers.IO) {
        val remaining = state.value.filterNot { it.id == profile.id }
        store.write(remaining)
        state.value = remaining
    }

    suspend fun refresh(subscriptionUrl: String) = withContext(Dispatchers.IO) {
        val latest = importer.download(subscriptionUrl)
        val merged = state.value.filterNot { it.subscription == subscriptionUrl } + latest
        store.write(merged)
        state.value = merged
    }
}
