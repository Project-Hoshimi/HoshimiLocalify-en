package io.github.tokanada.hoshimi.localify.mainUtils

import kotlinx.serialization.json.Json

val json = Json {
    encodeDefaults = true
    ignoreUnknownKeys = true
}
