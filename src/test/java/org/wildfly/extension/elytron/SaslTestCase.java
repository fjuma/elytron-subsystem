/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.extension.elytron;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;
import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class SaslTestCase extends AbstractSubsystemTest {

    public SaslTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    private KernelServices services = null;

    private void init() throws Exception {
        String filesystemFile = RealmsTestCase.class.getResource("/org/wildfly/extension/elytron/filesystem-realm").getFile();
        new ClassLoadingAttributeDefinitionsMock(); // mock classloader obtaining
        String subsystemXml =
                "<subsystem xmlns=\"" + ElytronExtension.NAMESPACE + "\">\n" +
                "    <security-domains>\n" +
                "        <security-domain name=\"MyDomain\" default-realm=\"MyRealm\" permission-mapper=\"PermMapper\">\n" +
                "            <realm name=\"MyRealm\"/>\n" +
                "        </security-domain>\n" +
                "    </security-domains>\n" +
                "    <security-realms>\n" +
                "        <filesystem-realm name=\"MyRealm\" levels=\"2\">\n" +
                "            <file path=\"" + filesystemFile + "\" />\n" +
                "        </filesystem-realm>\n" +
                "    </security-realms>\n" +
                "    <mappers>\n" +
                "        <custom-permission-mapper name=\"PermMapper\" class-name=\"org.wildfly.extension.elytron.SaslTestCase$PermMapper\"/>\n" +
                "    </mappers>\n" +
                "    <sasl>\n" +
                "        <provider-sasl-server-factory name=\"MySaslServer\"/>\n" +
                "        <sasl-server-authentication name=\"MySaslAuth\" security-domain=\"MyDomain\" sasl-server-factory=\"MySaslServer\">\n" +
                "            <mechanism-configuration>\n" +
                "                <mechanism mechanism-name=\"PLAIN\">\n" +
                "                    <mechanism-realm realm-name=\"TestingRealm1\"/>\n" +
                "                </mechanism>\n" +
                "                <mechanism mechanism-name=\"DIGEST\">\n" +
                "                    <mechanism-realm realm-name=\"TestingRealm1\"/>\n" +
                "                </mechanism>\n" +
                "            </mechanism-configuration>\n" +
                "        </sasl-server-authentication>\n" +
                "    </sasl>\n" +
                "</subsystem>\n";
        services = super.createKernelServicesBuilder(null).setSubsystemXml(subsystemXml).build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
    }

    @Test
    public void testSaslServerDigest() throws Exception {
        init();
        ServiceName serviceNameServer = Capabilities.SASL_SERVER_FACTORY_RUNTIME_CAPABILITY.getCapabilityServiceName("MySaslServer");
        SaslServerFactory serverFactory = (SaslServerFactory) services.getContainer().getService(serviceNameServer).getValue();

        Map<String, Object> serverClientProps = new HashMap<String, Object>();
        serverClientProps.put("javax.security.sasl.qop", "auth-conf");
        SaslServer server = serverFactory.createSaslServer(SaslMechanismInformation.Names.DIGEST_MD5,
                "protocol", "TestingRealm1", serverClientProps, serverCallbackHandler("user1", "TestingRealm1", "password1"));
        SaslClient client = Sasl.createSaslClient(new String[]{SaslMechanismInformation.Names.DIGEST_MD5},
                "user1", "protocol", "TestingRealm1", serverClientProps, clientCallbackHandler("user1", "TestingRealm1", "password1"));

        testSaslServerClient(server, client);
    }

    @Test
    public void testSaslAuthenticationPlain() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SASL_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY.getCapabilityServiceName("MySaslAuth");
        SaslAuthenticationFactory authFactory = (SaslAuthenticationFactory) services.getContainer().getService(serviceName).getValue();

        SaslServer server = authFactory.createMechanism(SaslMechanismInformation.Names.PLAIN);
        SaslClient client = Sasl.createSaslClient(new String[]{SaslMechanismInformation.Names.PLAIN},
                "firstUser", "protocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallbackHandler("firstUser", "TestingRealm1", "clearPassword"));

        testSaslServerClient(server, client);
    }

    @Test
    @Ignore("Waiting for AvailableRealmsCallback in Digest server (or PropertiesSaslServerFactory)")
    public void testSaslAuthenticationDigest() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SASL_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY.getCapabilityServiceName("MySaslAuth");
        SaslAuthenticationFactory authFactory = (SaslAuthenticationFactory) services.getContainer().getService(serviceName).getValue();

        SaslServer server = authFactory.createMechanism(SaslMechanismInformation.Names.DIGEST_SHA);
        SaslClient client = Sasl.createSaslClient(new String[]{SaslMechanismInformation.Names.DIGEST_SHA},
                "user1", "protocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallbackHandler("user1", "TestingRealm1", "password1"));

        testSaslServerClient(server, client);
    }

    @Test
    public void testSaslAuthenticationScram() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SASL_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY.getCapabilityServiceName("MySaslAuth");
        SaslAuthenticationFactory authFactory = (SaslAuthenticationFactory) services.getContainer().getService(serviceName).getValue();

        SaslServer server = authFactory.createMechanism(SaslMechanismInformation.Names.SCRAM_SHA_1);
        SaslClient client = Sasl.createSaslClient(new String[]{SaslMechanismInformation.Names.SCRAM_SHA_1},
                "firstUser", "protocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallbackHandler("firstUser", "TestingRealm1", "clearPassword"));

        testSaslServerClient(server, client);
    }

    private void testSaslServerClient(SaslServer server, SaslClient client) throws SaslException {
        byte[] message = new byte[]{};
        if (client.hasInitialResponse()) message = client.evaluateChallenge(message);
        while(!server.isComplete() || !client.isComplete()) {
            if (!server.isComplete()) message = server.evaluateResponse(message);
            if (!client.isComplete()) message = client.evaluateChallenge(message);
        }
    }

    private CallbackHandler serverCallbackHandler(String username, String realm, String password) {
        return callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    Assert.assertEquals(username, ((NameCallback) callback).getDefaultName());
                } else if (callback instanceof RealmCallback) {
                    Assert.assertEquals(realm, ((RealmCallback) callback).getDefaultText());
                } else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(password.toCharArray());
                } else if (callback instanceof AuthorizeCallback) {
                    ((AuthorizeCallback) callback).setAuthorized(((AuthorizeCallback) callback).getAuthorizationID().equals(((AuthorizeCallback) callback).getAuthenticationID()));
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        };
    }

    private CallbackHandler clientCallbackHandler(String username, String realm, String password) throws Exception {
        return callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    ((NameCallback) callback).setName(username);
                } else if (callback instanceof RealmCallback) {
                    ((RealmCallback) callback).setText(realm);
                } else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(password.toCharArray());
                } else if (callback instanceof CredentialCallback && ClearPassword.ALGORITHM_CLEAR.equals(((CredentialCallback) callback).getAlgorithm())) {
                    try {
                        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
                        Password pass = factory.generatePassword(new ClearPasswordSpec(password.toCharArray()));

                        ((CredentialCallback) callback).setCredential(new PasswordCredential(pass));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                } else if (callback instanceof ChannelBindingCallback) {
                    ((ChannelBindingCallback) callback).setBindingType("type");
                    ((ChannelBindingCallback) callback).setBindingData(new byte[]{0x12,0x34});
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        };
    }

    // classloader obtaining must be mocked in AbstractSubsystemTest to load classes from testsuite
    private static class ClassLoadingAttributeDefinitionsMock extends MockUp<ClassLoadingAttributeDefinitions> {
        @Mock
        static ClassLoader resolveClassLoader(String module, String slot) {
            return SaslTestCase.class.getClassLoader();
        }
    }

    public static class PermMapper implements PermissionMapper {
        @Override
        public PermissionVerifier mapPermissions(Principal principal, Roles roles) {
            return permission -> permission instanceof LoginPermission;
        }
    }
}
