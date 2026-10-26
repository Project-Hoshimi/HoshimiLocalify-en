package io.github.cylear.hoshimi.localify.ui.pages.subPages

import android.content.res.Configuration.UI_MODE_NIGHT_NO
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.cylear.hoshimi.localify.MainActivity
import io.github.cylear.hoshimi.localify.R
import io.github.cylear.hoshimi.localify.getConfigState
import io.github.cylear.hoshimi.localify.models.IdolyprideConfig
import io.github.cylear.hoshimi.localify.ui.components.IPGroupBox
import io.github.cylear.hoshimi.localify.ui.components.IPSwitch
import io.github.cylear.hoshimi.localify.ui.components.IPTextInput
import androidx.compose.ui.text.input.KeyboardType


@Composable
fun PrivateServerPage(modifier: Modifier = Modifier,
                     context: MainActivity? = null,
                     previewData: IdolyprideConfig? = null,
                     bottomSpacerHeight: Dp = 120.dp,
                     screenH: Dp = 1080.dp) {
    val config = getConfigState(context, previewData)

    LazyColumn(modifier = modifier
        .sizeIn(maxHeight = screenH)
        .fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        item {
            Text(
                text = stringResource(R.string.private_server_note),
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(Modifier.height(6.dp))
        }

        item {
            IPGroupBox(modifier, stringResource(R.string.private_server)) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    IPSwitch(modifier, stringResource(R.string.private_server_enabled),
                        checked = config.value.privateServerEnabled) { v ->
                        context?.onPrivateServerEnabledChanged(v)
                    }

                    Text(stringResource(R.string.private_server_url), fontSize = 14.sp)
                    IPTextInput(
                        value = config.value.privateServerUrl,
                        onValueChange = { context?.onPrivateServerUrlChanged(it) },
                        label = { Text(stringResource(R.string.private_server_url_hint)) },
                        modifier = modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
                    )

                    Text(stringResource(R.string.private_server_ca_pem), fontSize = 14.sp)

                    var localValue by remember { mutableStateOf(config.value.privateServerCaPem) }
                    var isUserInput by remember { mutableStateOf(false) }
                    LaunchedEffect(config.value.privateServerCaPem) {
                        if (!isUserInput) {
                            localValue = config.value.privateServerCaPem
                        }
                        isUserInput = false
                    }
                    OutlinedTextField(
                        value = localValue,
                        onValueChange = { newValue ->
                            isUserInput = true
                            localValue = newValue
                            context?.onPrivateServerCaPemChanged(newValue)
                        },
                        minLines = 5,
                        maxLines = 12,
                        modifier = modifier.fillMaxWidth(),
                        textStyle = TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    )
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