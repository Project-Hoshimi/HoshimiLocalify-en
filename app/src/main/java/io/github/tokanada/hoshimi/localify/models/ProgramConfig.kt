package io.github.tokanada.hoshimi.localify.models

import io.github.tokanada.hoshimi.localify.mainUtils.json
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.encodeStructure
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Serializable
data class ProgramConfig(
    @SerialName("checkBuiltInAssets")
    var useBuiltInAssets: Boolean = false,
    var useAPIAssets: Boolean = true,
    var useAPIAssetsURL: String = "",
    var cleanLocalAssets: Boolean = false,
    var currentResourceVersion: String = "",

    // var localAPIAssetsVersion: String = "",
    var p: Boolean = false
)

class ProgramConfigSerializer(
    private val excludes: List<String> = emptyList(),
) : KSerializer<ProgramConfig> {
    override val descriptor: SerialDescriptor = ProgramConfig.serializer().descriptor
    override fun serialize(encoder: Encoder, value: ProgramConfig) {
        val jsonObject = json.encodeToJsonElement(value).jsonObject
        encoder.encodeStructure(descriptor) {
            jsonObject.keys.forEachIndexed { index, k ->
                if (k in excludes) return@forEachIndexed
                encodeSerializableElement(descriptor, index, JsonElement.serializer(), jsonObject[k]!!)
            }
        }
    }

    override fun deserialize(decoder: Decoder): ProgramConfig {
        return ProgramConfig.serializer().deserialize(decoder)
    }
}
