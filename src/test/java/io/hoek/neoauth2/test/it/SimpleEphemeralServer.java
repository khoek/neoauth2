package io.hoek.neoauth2.test.it;

import com.sun.net.httpserver.HttpServer;
import lombok.SneakyThrows;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;

public abstract class SimpleEphemeralServer {

    public static final String LOCALHOST = "localhost";

    private final HttpServer server;

    @SneakyThrows
    public SimpleEphemeralServer() {
        ServerSocket socket = new ServerSocket(0);
        socket.setReuseAddress(true);
        int port = socket.getLocalPort();
        socket.close();

        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(null);
        setup(server);
    }

    protected abstract void setup(HttpServer server);

    @SneakyThrows
    public URI getEndpointUri(String endpointPath) {
        return new URI("http://" + LOCALHOST + ":" + server.getAddress().getPort() + endpointPath);
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(1);
    }
}
