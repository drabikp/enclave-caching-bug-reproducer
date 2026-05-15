package com.parkdots.repro;

import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.util.Context;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import reactor.core.publisher.Mono;

/**
 * {@link HttpClient} that delegates to a Netty-backed client and increments
 * {@link KvOperationCounter} for each outgoing request. Wired in via the
 * {@code HttpClientProvider} SPI ({@link CountingHttpClientProvider}).
 */
final class CountingHttpClient implements HttpClient {

    private final HttpClient delegate;

    CountingHttpClient() {
        // Explicit Netty builder bypasses HttpClient.createDefault() and therefore the
        // ServiceLoader-based provider discovery — no infinite recursion.
        this.delegate = new NettyAsyncHttpClientBuilder().build();
    }

    @Override
    public Mono<HttpResponse> send(HttpRequest request) {
        KvOperationCounter.increment(request.getUrl().toString());
        return delegate.send(request);
    }

    @Override
    public Mono<HttpResponse> send(HttpRequest request, Context context) {
        KvOperationCounter.increment(request.getUrl().toString());
        return delegate.send(request, context);
    }

    @Override
    public HttpResponse sendSync(HttpRequest request, Context context) {
        KvOperationCounter.increment(request.getUrl().toString());
        return delegate.sendSync(request, context);
    }
}
