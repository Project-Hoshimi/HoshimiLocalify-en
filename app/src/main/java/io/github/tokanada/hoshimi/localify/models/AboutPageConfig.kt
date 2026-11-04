package io.github.tokanada.hoshimi.localify.models

import kotlinx.serialization.Serializable

@Serializable
data class AboutPageConfig(
    val plugin_repo: String = "https://github.com/Project-Hoshimi/HoshimiLocalify-en",
    val main_contributors: List<MainContributors> = listOf(),
    val contrib_img: ContribImg = ContribImg(
        "https://contrib.rocks/image?repo=Project-Hoshimi/HoshimiLocalify-en",
    )
)

@Serializable
data class MainContributors(
    val name: String,
    val links: List<Links>
)

@Serializable
data class ContribImg(
    val plugin: String,
    /** Extra avatar image URLs drawn after the contrib.rocks graph (fork contributors). */
    val extra_avatars: List<String> = listOf()
)

@Serializable
data class Links(
    val name: String,
    val link: String
)
