package org.wildfly.extension.elytron;

import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class SslTestCase extends AbstractSubsystemTest {

    private final int TESTING_PORT = 18201;

    public SslTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    private KernelServices services = null;

    private String keyStoreFile = SslTestCase.class.getResource("/org/wildfly/extension/elytron/testingCaJks.keystore").getFile();
    private String trustStoreFile = SslTestCase.class.getResource("/org/wildfly/extension/elytron/testingCaJceks.truststore").getFile();

    // TODO replace by factory from elytron when will be client side available
    private SSLSocketFactory getClientFactory() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, trustAllCerts, null);
        return clientContext.getSocketFactory();
    }

    @Test
    public void testSslService() throws Exception {
        String subsystemXml = "<subsystem xmlns=\"" + ElytronExtension.NAMESPACE + "\">\n" +
                "    <tls>\n" +
                "        <keystores>\n" +
                "            <keystore name=\"TestingCaKeyStore\" type=\"JKS\" password=\"123456\">\n" +
                "                <file path=\"" + keyStoreFile + "\"/>\n" +
                "            </keystore>\n" +
                "            <keystore name=\"TestingCaTrustStore\" type=\"JCEKS\" password=\"1234567\">\n" +
                "                <file path=\"" + trustStoreFile + "\"/>\n" +
                "            </keystore>\n" +
                "        </keystores>\n" +
                "        <key-managers>\n" +
                "            <key-manager name=\"MyKeyManager\" algorithm=\"SunX509\" keystore=\"TestingCaKeyStore\" password=\"12345678\"/>\n" +
                "        </key-managers>\n" +
                "        <trust-managers>\n" +
                "            <trust-manager name=\"MyTrustManager\" algorithm=\"SunX509\" keystore=\"TestingCaTrustStore\"/>\n" +
                "        </trust-managers>\n" +
                "        <server-ssl-contexts>\n" +
                "            <server-ssl-context name=\"ServerSslContext\" protocols=\"SSLv2 SSLv3 TLSv1 TLSv1_3 TLSv1_2 TLSv1_1\" key-managers=\"MyKeyManager\" trust-managers=\"MyTrustManager\"/>\n" +
                //"            <server-ssl-context name=\"ClientSslContext\" protocols=\"SSLv2 SSLv3 TLSv1 TLSv1_3 TLSv1_2 TLSv1_1\" trust-managers=\"MyTrustManager\"/>\n" +
                "        </server-ssl-contexts>\n" +
                "    </tls>\n" +
                "</subsystem>\n";

        services = super.createKernelServicesBuilder(null).setSubsystemXml(subsystemXml).build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }

        ServiceName serverServiceName = Capabilities.SSL_CONTEXT_RUNTIME_CAPABILITY.getCapabilityServiceName("ServerSslContext");
        SSLContext serverSslContext = (SSLContext) services.getContainer().getService(serverServiceName).getValue();
        Assert.assertNotNull(serverSslContext);
        SSLServerSocketFactory serverSocketFactory = serverSslContext.getServerSocketFactory();

        /*
        ServiceName clientServiceName = Capabilities.SSL_CONTEXT_RUNTIME_CAPABILITY.getCapabilityServiceName("ClientSslContext");
        SSLContext clientSslContext = (SSLContext) services.getContainer().getService(clientServiceName).getValue();
        Assert.assertNotNull(clientSslContext);
        SSLSocketFactory clientSocketFactory = clientSslContext.getSocketFactory();
        */

        SSLSocketFactory clientSocketFactory = getClientFactory();

        ServerSocket listeningSocket = serverSocketFactory.createServerSocket();
        listeningSocket.bind(new InetSocketAddress("localhost", TESTING_PORT));

        SSLSocket clientSocket = (SSLSocket) clientSocketFactory.createSocket("localhost", TESTING_PORT);
        clientSocket.setUseClientMode(true);
        SSLSocket serverSocket = (SSLSocket) listeningSocket.accept();
        serverSocket.setUseClientMode(false);

        ExecutorService clientExecutorService = Executors.newSingleThreadExecutor();
        Future<byte[]> clientFuture = clientExecutorService.submit(() -> {
            try {
                byte[] received = new byte[2];
                clientSocket.getOutputStream().write(new byte[]{0x12, 0x34});
                serverSocket.getInputStream().read(received);
                return received;
            } catch (Exception e) {
                throw new RuntimeException("Client exception", e);
            }
        });

        ExecutorService serverExecutorService = Executors.newSingleThreadExecutor();
        Future<byte[]> serverFuture = serverExecutorService.submit(() -> {
            try {
                byte[] received = new byte[2];
                serverSocket.getInputStream().read(received);
                clientSocket.getOutputStream().write(new byte[]{0x56, 0x78});
                return received;
            } catch (Exception e) {
                throw new RuntimeException("Server exception", e);
            }
        });

        Assert.assertArrayEquals(new byte[]{0x12, 0x34}, serverFuture.get());
        Assert.assertArrayEquals(new byte[]{0x56, 0x78}, clientFuture.get());

        serverSocket.close();
        listeningSocket.close();
        clientSocket.close();
    }
}