package io.github.tokanada.hoshimi.localify.ui.pages.subPages

import android.content.res.Configuration.UI_MODE_NIGHT_NO
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.tokanada.hoshimi.localify.MainActivity
import io.github.tokanada.hoshimi.localify.R
import io.github.tokanada.hoshimi.localify.models.IdolyprideConfig
import io.github.tokanada.hoshimi.localify.ui.components.IPGroupBox


@Composable
fun PrivateServerPage(modifier: Modifier = Modifier,
                     context: MainActivity? = null,
                     previewData: IdolyprideConfig? = null,
                     bottomSpacerHeight: Dp = 120.dp,
                     screenH: Dp = 1080.dp) {
    LazyColumn(modifier = modifier
        .sizeIn(maxHeight = screenH)
        .fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        item {
            IPGroupBox(modifier, stringResource(R.string.private_server)) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = stringResource(R.string.private_server_managed_in_game),
                        fontSize = 14.sp
                    )

                    Text(
                        text = stringResource(R.string.private_server_step_open_game),
                        fontSize = 14.sp
                    )

                    Text(
                        text = stringResource(R.string.private_server_step_switch_server),
                        fontSize = 14.sp
                    )

                    Text(
                        text = stringResource(R.string.private_server_step_pick_or_add),
                        fontSize = 14.sp
                    )

                    Spacer(Modifier.height(8.dp))

                    Text(
                        text = stringResource(R.string.private_server_switch_warning),
                        fontSize = 14.sp,
                        color = MaterialTheme.colorScheme.error
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
