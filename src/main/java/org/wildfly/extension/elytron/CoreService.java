/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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
import static org.jboss.as.server.Services.addServerExecutorDependency;

import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;

import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.jboss.threads.JBossExecutors;
import org.jboss.threads.JBossThreadFactory;
import org.wildfly.security.WildFlyElytronProvider;

/**
 * Core {@link Service} for the Elytron subsystem.
 *
 * Initially focused on provider registration but could cover further core initialisation requirements.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class CoreService implements Service<Void> {

    static final ServiceName SERVICE_NAME = ElytronExtension.BASE_SERVICE_NAME.append(ElytronDescriptionConstants.CORE_SERVICE);
    static final ServiceName CORE_SCHEDULED_EXECUTOR_SERVICE_NAME = ElytronExtension.BASE_SERVICE_NAME.append(ElytronDescriptionConstants.CORE_SCHEDULED_EXECUTOR_SERVICE);

    private volatile Provider provider;

    private final ThreadGroup threadGroup = new ThreadGroup("CoreService ThreadGroup");
    private final ThreadFactory threadFactory = doPrivileged((PrivilegedAction<JBossThreadFactory>) ()
            -> new JBossThreadFactory(threadGroup, Boolean.FALSE, null, "%G - %t", null, null));

    @Override
    public void start(StartContext context) throws StartException {
        provider = new WildFlyElytronProvider();
        SecurityActions.doPrivileged((PrivilegedAction<Void>) () -> {
            Security.addProvider(provider);
            return null;
        });

        final ServiceTarget serviceTarget = context.getChildTarget();
        final CoreScheduledExecutorService scheduledExecutorService = new CoreScheduledExecutorService(threadFactory);
        final ServiceBuilder<ScheduledExecutorService> serviceBuilder = serviceTarget
                .addService(CORE_SCHEDULED_EXECUTOR_SERVICE_NAME, scheduledExecutorService)
                .setInitialMode(ServiceController.Mode.ACTIVE);
        addServerExecutorDependency(serviceBuilder, scheduledExecutorService.executorInjector, false);
        serviceBuilder.install();
    }

    @Override
    public void stop(StopContext context) {
        SecurityActions.doPrivileged((PrivilegedAction<Void>) () -> {
            Security.removeProvider(provider.getName());
            return null;
        });
        provider = null;
    }

    @Override
    public Void getValue() throws IllegalStateException, IllegalArgumentException {
        return null;
    }

    private static final class CoreScheduledExecutorService implements Service<ScheduledExecutorService> {
        private final ThreadFactory threadFactory;
        private final InjectedValue<ExecutorService> executorInjector = new InjectedValue<>();
        private ScheduledThreadPoolExecutor scheduledExecutorService;

        private CoreScheduledExecutorService(ThreadFactory threadFactory) {
            this.threadFactory = threadFactory;
        }

        @Override
        public synchronized void start(final StartContext context) throws StartException {
            scheduledExecutorService = new ScheduledThreadPoolExecutor(1, threadFactory);
            scheduledExecutorService.setRemoveOnCancelPolicy(true);
            scheduledExecutorService.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        }

        @Override
        public synchronized void stop(final StopContext context) {
            Runnable r = () -> {
                try {
                    scheduledExecutorService.shutdown();
                } finally {
                    scheduledExecutorService = null;
                    context.complete();
                }
            };
            try {
                executorInjector.getValue().execute(r);
            } catch (RejectedExecutionException e) {
                r.run();
            } finally {
                context.asynchronous();
            }
        }

        @Override
        public synchronized ScheduledExecutorService getValue() throws IllegalStateException {
            return JBossExecutors.protectedScheduledExecutorService(scheduledExecutorService);
        }
    }
}
