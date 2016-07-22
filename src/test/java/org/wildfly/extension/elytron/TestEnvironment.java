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

import static java.security.AccessController.doPrivileged;

import mockit.Mock;
import mockit.MockUp;

import org.jboss.as.server.Services;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.ControllerInitializer;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceTarget;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.threads.JBossThreadFactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.PrivilegedAction;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

class TestEnvironment extends AdditionalInitialization {

    static final int LDAP_PORT = 11391;

    @Override
    protected ControllerInitializer createControllerInitializer() {
        ControllerInitializer initializer = new ControllerInitializer();

        try {
            URL fsr = getClass().getResource("filesystem-realm-empty");
            if (fsr != null) emptyDirectory(Paths.get(fsr.getFile()));
        } catch (Exception e) {
            throw new RuntimeException("Could ensure empty testing filesystem directory", e);
        }

        try {
            initializer.addPath("jboss.server.config.dir", getClass().getResource(".").getFile(), null);
        } catch (Exception e) {
            throw new RuntimeException("Could not create test config directory", e);
        }

        return initializer;
    }

    @Override
    protected void addExtraServices(ServiceTarget target) {
        // Needed by the CoreScheduledExecutorService
        final ThreadFactory threadFactory = doPrivileged((PrivilegedAction<ThreadFactory>) () ->
           new JBossThreadFactory(new ThreadGroup("TestServerExecutorService ThreadGroup"), Boolean.FALSE, null, "%G - %t", null, null)
        );
        final TestServerExecutorService testServerExecutorService = new TestServerExecutorService(threadFactory);
        target.addService(Services.JBOSS_SERVER_EXECUTOR, testServerExecutorService).install();
    }

    public static LdapService startLdapService() {
        try {
            return LdapService.builder()
                    .setWorkingDir(new File("./target/apache-ds/working"))
                    .createDirectoryService("Test Service")
                    .addPartition("Elytron", "dc=elytron,dc=wildfly,dc=org", 5, "uid")
                    .importLdif(TestEnvironment.class.getResourceAsStream("ldap.ldif"))
                    .addTcpServer("Default TCP", "localhost", LDAP_PORT)
                    .start();
        } catch (Exception e) {
            throw new RuntimeException("Could not start LDAP embedded server.", e);
        }
    }

    private void emptyDirectory(Path directory) throws IOException {
        Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    // classloader obtaining mock to load classes from testsuite
    private static class ClassLoadingAttributeDefinitionsMock extends MockUp<ClassLoadingAttributeDefinitions> {
        @Mock
        static ClassLoader resolveClassLoader(String module) {
            return SaslTestCase.class.getClassLoader();
        }
    }

    static void mockCallerModuleClassloader() {
        new ClassLoadingAttributeDefinitionsMock();
    }

    private static class TestServerExecutorService implements Service<ExecutorService> {

        private final ThreadFactory threadFactory;
        private ExecutorService executorService;

        private TestServerExecutorService(ThreadFactory threadFactory) {
            this.threadFactory = threadFactory;
        }

        @Override
        public synchronized void start(StartContext context) throws StartException {
            executorService = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 20L, TimeUnit.SECONDS,
                    new SynchronousQueue<Runnable>(), threadFactory);
        }

        @Override
        public synchronized void stop(final StopContext context) {

            if (executorService != null) {
                context.asynchronous();
                Thread executorShutdown = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            executorService.shutdown();
                        } finally {
                            executorService = null;
                            context.complete();
                        }
                    }
                }, "TestServerExecutorService Shutdown Thread");
                executorShutdown.start();
            }
        }

        @Override
        public synchronized ExecutorService getValue() throws IllegalStateException, IllegalArgumentException {
            return executorService;
        }
    }
}