package io.github.tokanada.hoshimi.localify.ui.pages.subPages

import android.content.res.Configuration.UI_MODE_NIGHT_NO
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.tokanada.hoshimi.localify.MainActivity
import io.github.tokanada.hoshimi.localify.R
import io.github.tokanada.hoshimi.localify.appendSuggestedServerUrl
import io.github.tokanada.hoshimi.localify.getConfigState
import io.github.tokanada.hoshimi.localify.models.IdolyprideConfig
import io.github.tokanada.hoshimi.localify.ui.components.IPButton
import io.github.tokanada.hoshimi.localify.ui.components.IPGroupBox
import androidx.compose.ui.text.input.KeyboardType


@Composable
fun PrivateServerPage(modifier: Modifier = Modifier,
                     context: MainActivity? = null,
                     previewData: IdolyprideConfig? = null,
                     bottomSpacerHeight: Dp = 120.dp,
                     screenH: Dp = 1080.dp) {
    val config = getConfigState(context, previewData)
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    LazyColumn(modifier = modifier
        .sizeIn(maxHeight = screenH)
        .fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        item {
            Text(
                text = "Servers are chosen in game: tap \"Switch server\" on the title screen. " +
                        "URLs added here appear in that list marked \"from app\"; picking one there " +
                        "checks its certificate and asks before switching. Adding a URL here does " +
                        "not switch servers.",
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(Modifier.height(6.dp))
        }

        item {
            IPGroupBox(modifier, stringResource(R.string.private_server)) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Server URL", fontSize = 14.sp)

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = input,
                            onValueChange = {
                                input = it
                                error = null
                            },
                            singleLine = true,
                            label = { Text("Server URL") },
                            placeholder = { Text("https://example.com or https://192.168.1.10:8443") },
                            modifier = modifier.weight(1f),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
                        )

                        IPButton(
                            onClick = {
                                val trimmed = input.trim()
                                if (!trimmed.startsWith("https://") && !trimmed.startsWith("http://")) {
                                    error = "Enter an http(s):// URL"
                                } else {
                                    val current = config.value.suggestedServerUrls
                                    val updated = appendSuggestedServerUrl(current, trimmed)
                                    if (updated.size != current.size) {
                                        context?.onSuggestedServerUrlsChanged(updated)
                                        input = ""
                                    }
                                    error = null
                                }
                            },
                            text = "Add",
                            modifier = modifier.height(56.dp).width(88.dp)
                        )
                    }

                    error?.let {
                        Text(
                            text = it,
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.error
                        )
                    }

                    if (config.value.suggestedServerUrls.isNotEmpty()) {
                        Spacer(Modifier.height(4.dp))
                    }

                    config.value.suggestedServerUrls.forEach { url ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = url,
                                fontSize = 14.sp,
                                modifier = modifier.weight(1f)
                            )

                            IPButton(
                                onClick = {
                                    context?.onSuggestedServerUrlsChanged(
                                        config.value.suggestedServerUrls.filterNot { it == url }
                                    )
                                },
                                text = "Remove",
                                modifier = modifier.height(40.dp).width(96.dp)
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(6.dp))
        }

        item {
            Spacer(modifier = modifier.height(bottomSpacerHeight))
        }
    }
}


@Preview(showBackground = true, uiMode = UI_MODE_NIGHT_NO)
@Composable
fun PrivateServerPagePreview() {
    PrivateServerPage(previewData = IdolyprideConfig())
}
