package com.parkdots.repro;

import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpClientProvider;
import com.azure.core.util.HttpClientOptions;

/**
 * Service-loader entry point that makes {@link CountingHttpClient} the default Azure SDK
 * {@code HttpClient}. Registered under
 * {@code META-INF/services/com.azure.core.http.HttpClientProvider}.
 *
 * <p>Azure's {@code HttpClient.createDefault()} loads providers via {@code ServiceLoader} and uses
 * the first one it finds. Bundling this provider in the reproducer's shaded jar before any other
 * provider (or registering the META-INF/services file in our resources) ensures it wins.
 */
public final class CountingHttpClientProvider implements HttpClientProvider {

    @Override
    public HttpClient createInstance() {
        return new CountingHttpClient();
    }

    @Override
    public HttpClient createInstance(HttpClientOptions clientOptions) {
        return new CountingHttpClient();
    }
}
