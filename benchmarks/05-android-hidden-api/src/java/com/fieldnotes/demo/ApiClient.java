package com.fieldnotes.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/** Log in with the device id and app key, then use the returned token as a bearer token. */
final class ApiClient {
    private static final String APP_KEY_PREFIX = "fn-demo";
    private static final String APP_KEY_SUFFIX = "not-a-real-key";

    private String token;

    private static String appKey() {
        return APP_KEY_PREFIX + "-" + APP_KEY_SUFFIX;
    }

    String post(String address, String body, boolean authorized) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(address).openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("X-App-Key", appKey());
        if (authorized) {
            connection.setRequestProperty("Authorization", "Bearer " + token);
        }
        try (OutputStream stream = connection.getOutputStream()) {
            stream.write(body.getBytes("UTF-8"));
        }
        try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"))) {
            return reader.readLine();
        }
    }

    void login(String deviceId) throws IOException {
        String reply = post(Endpoints.session(), "{\"device_id\":\"" + deviceId + "\"}", false);
        int start = reply.indexOf("\"token\":\"") + 9;
        token = reply.substring(start, reply.indexOf('"', start));
    }

    String sync(String notes) throws IOException {
        return post(Endpoints.sync(), notes, true);
    }

    String diagnostics() throws IOException {
        return post(Endpoints.diagnostics(), "{}", true);
    }
}
