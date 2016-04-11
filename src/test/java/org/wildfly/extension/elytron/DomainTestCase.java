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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.permission.PermissionVerifier;

import javax.security.auth.x500.X500Principal;
import java.io.FilePermission;
import java.security.Principal;


/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class DomainTestCase extends AbstractSubsystemTest {

    public DomainTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    private KernelServices services = null;

    private String filesystemFile = RealmsTestCase.class.getResource("/org/wildfly/extension/elytron/filesystem-realm").getFile();
    private String propertiesFile = RealmsTestCase.class.getResource("/org/wildfly/extension/elytron/testingrealm1-users.properties").getFile();

    private void init() throws Exception {
        new ClassLoadingAttributeDefinitionsMock(); // mock classloader obtaining
        String subsystemXml = "<subsystem xmlns=\"" + ElytronExtension.NAMESPACE + "\">\n" +
                "    <security-domains>\n" +
                "        <security-domain name=\"MyDomain\" default-realm=\"FileRealm\" realm-mapper=\"MyRealmMapper\" permission-mapper=\"MyPermissionMapper\"  pre-realm-name-rewriter=\"NameRewriterXY\" post-realm-name-rewriter=\"NameRewriterYU\">\n" +
                "            <realm name=\"FileRealm\" role-decoder=\"MyRoleDecoder\" role-mapper=\"MyRoleMapper\"/>\n" +
                "            <realm name=\"PropRealm\" name-rewriter=\"NameRewriterRealmRemover\"/>\n" +
                "        </security-domain>\n" +
                "        <security-domain name=\"X500Domain\" default-realm=\"FileRealm\" principal-decoder=\"MyX500PrincipalDecoder\">\n" +
                "            <realm name=\"FileRealm\"/>\n" +
                "        </security-domain>\n" +
                "    </security-domains>\n" +
                "    <security-realms>\n" +
                "        <filesystem-realm name=\"FileRealm\" levels=\"2\">\n" +
                "            <file path=\"" + filesystemFile + "\" />\n" +
                "        </filesystem-realm>\n" +
                "        <properties-realm name=\"PropRealm\">\n" +
                "            <users-properties path=\"" + propertiesFile + "\" />\n" +
                "        </properties-realm>\n" +
                "    </security-realms>\n" +
                "    <mappers>\n" +
                "        <regex-name-rewriter name=\"NameRewriterXY\" pattern=\"x(.*)\" replacement=\"y$1\"/>\n" +
                "        <regex-name-rewriter name=\"NameRewriterYU\" pattern=\"y(.*)\" replacement=\"u$1\"/>\n" +
                "        <regex-name-rewriter name=\"NameRewriterRealmRemover\" pattern=\"(.*)@.*\" replacement=\"$1\"/>\n" +
                "        <simple-regex-realm-mapper name=\"MyRealmMapper\" pattern=\".*@(.*)\"/>\n" +
                "        <simple-role-decoder name=\"MyRoleDecoder\" attribute=\"roles\"/>\n" +
                "        <add-prefix-role-mapper name=\"RolePrefixer\" prefix=\"prefix\"/>\n" +
                "        <add-suffix-role-mapper name=\"RoleSuffixer\" suffix=\"suffix\"/>\n" +
                "        <aggregate-role-mapper name=\"MyRoleMapper\">\n" +
                "            <role-mapper name=\"RolePrefixer\"/>\n" +
                "            <role-mapper name=\"RoleSuffixer\"/>\n" +
                "        </aggregate-role-mapper>\n" +
                "        <custom-permission-mapper name=\"MyPermissionMapper\" class-name=\"org.wildfly.extension.elytron.DomainTestCase$MyPermissionMapper\"/>\n" +
                "        <x500-attribute-principal-decoder name=\"MyX500PrincipalDecoder\" oid=\"2.5.4.3\" joiner=\",\" maximum-segments=\"6\" />\n" +
                "    </mappers>\n" +
                "</subsystem>\n";

        services = super.createKernelServicesBuilder(null).setSubsystemXml(subsystemXml).build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
    }

    @Test
    public void testDefaultRealmIdentity() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("MyDomain");
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        ServerAuthenticationContext context = domain.createNewAuthenticationContext();
        context.setAuthenticationName("firstUser"); // from FileRealm
        Assert.assertTrue(context.exists());
        context.succeed();
        SecurityIdentity identity = context.getAuthorizedIdentity();
        Assert.assertEquals("John", identity.getAttributes().get("firstName").get(0));
        Assert.assertEquals("Smith", identity.getAttributes().get("lastName").get(0));

        Roles roles = identity.getRoles();
        Assert.assertTrue(roles.contains("prefixEmployeesuffix"));
        Assert.assertTrue(roles.contains("prefixManagersuffix"));
        Assert.assertTrue(roles.contains("prefixAdminsuffix"));
        Assert.assertEquals("firstUser", identity.getPrincipal().getName());

        Assert.assertTrue(identity.implies(new FilePermission("test", "read")));
        Assert.assertFalse(identity.implies(new FilePermission("test", "write")));
    }

    @Test
    public void testNonDefaultRealmIdentity() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("MyDomain");
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        MechanismConfiguration mechConf = MechanismConfiguration.builder()
                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("FileRealm").build())
                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("PropRealm").build())
                .build();
        ServerAuthenticationContext context = domain.createNewAuthenticationContext(mechConf);

        context.setMechanismRealmName("PropRealm");
        context.setAuthenticationName("xser1@PropRealm");
        Assert.assertTrue(context.exists());
        context.succeed();
        SecurityIdentity identity = context.getAuthorizedIdentity();
        Assert.assertEquals("yser1@PropRealm", identity.getPrincipal().getName()); // after pre-realm-name-rewriter only
    }

    @Test
    public void testNamePrincipalMapping() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("MyDomain");
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        Assert.assertFalse(domain.mapName("wrong").exists());
        Assert.assertFalse(domain.mapName("firstUser@wrongRealm").exists());
        Assert.assertTrue(domain.mapName("firstUser").exists());
        Assert.assertTrue(domain.mapName("user1@PropRealm").exists());
        Assert.assertTrue(domain.mapPrincipal(new NamePrincipal("user1@PropRealm")).exists());
    }

    @Test
    public void testX500PrincipalMapping() throws Exception {
        init();
        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("X500Domain");
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        Assert.assertTrue(domain.mapPrincipal(new X500Principal("cn=firstUser,ou=group")).exists());

    }

    // classloader obtaining must be mocked in AbstractSubsystemTest to load classes from testsuite
    private static class ClassLoadingAttributeDefinitionsMock extends MockUp<ClassLoadingAttributeDefinitions> {
        @Mock
        static ClassLoader resolveClassLoader(String module, String slot) {
            return DomainTestCase.class.getClassLoader();
        }
    }

    public static class MyPermissionMapper implements PermissionMapper {
        @Override
        public PermissionVerifier mapPermissions(Principal principal, Roles roles) {
            return permission -> roles.contains("prefixAdminsuffix") && permission.getActions().equals("read");
        }
    }

}
