package com.fieldnotes.demo;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.TextView;
import java.io.IOException;

public class MainActivity extends Activity {
    private final ApiClient client = new ApiClient();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setText(R.string.app_name);
        setContentView(view);
        // Anonymous classes, not lambdas: the dexer for API 23 cannot translate invokedynamic.
        new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                work();
                            }
                        })
                .start();
    }

    private void work() {
        SharedPreferences settings = getSharedPreferences("fieldnotes", MODE_PRIVATE);
        try {
            client.login(settings.getString("device_id", "unknown-device"));
            client.sync("{\"notes\":[]}");
            if (settings.getBoolean("debug_menu", false)) {
                client.diagnostics();
            }
        } catch (IOException error) {
            getWindow()
                    .getDecorView()
                    .post(
                            new Runnable() {
                                @Override
                                public void run() {
                                    finish();
                                }
                            });
        }
    }
}
