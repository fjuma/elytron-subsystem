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

import static org.jboss.as.controller.capability.RuntimeCapability.buildDynamicCapabilityName;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PROVIDERS_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_AUTHENTICATION_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.MODULE;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.SLOT;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.resolveClassLoader;
import static org.wildfly.extension.elytron.CommonAttributes.PROPERTIES;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.VALUE;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.ElytronExtension.getRequiredService;
import static org.wildfly.extension.elytron.SecurityActions.doPrivileged;

import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.jboss.msc.service.StartException;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityDomainHttpConfiguration;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.AggregateServerMechanismFactory;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.PropertiesServerMechanismFactory;
import org.wildfly.security.http.util.SecurityProviderServerMechanismFactory;
import org.wildfly.security.http.util.ServiceLoaderServerMechanismFactory;

/**
 * Resource definitions for loading and configuring the HTTP server side authentication mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class HttpServerDefinitions {

    static final SimpleAttributeDefinition HTTP_SERVER_FACTORY_FOR_CONFIG = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.HTTP_SERVER_FACTORY, ModelType.STRING, false)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(HTTP_SERVER_FACTORY_CAPABILITY, HTTP_SERVER_AUTHENTICATION_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition HTTP_SERVER_FACTORY_FOR_FACTORY = new SimpleAttributeDefinitionBuilder(HTTP_SERVER_FACTORY_FOR_CONFIG)
        .setCapabilityReference(HTTP_SERVER_FACTORY_CAPABILITY, HTTP_SERVER_FACTORY_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition PROVIDER_LOADER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROVIDER_LOADER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(PROVIDERS_CAPABILITY, HTTP_SERVER_FACTORY_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition SECURITY_DOMAIN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SECURITY_DOMAIN, ModelType.STRING, false)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, HTTP_SERVER_AUTHENTICATION_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition PATTERN_FILTER = new SimpleAttributeDefinitionBuilder(RegexAttributeDefinitions.PATTERN)
        .setXmlName(VALUE)
        .setName(ElytronDescriptionConstants.PATTERN_FILTER)
        .build();

    static final SimpleAttributeDefinition ENABLING = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ENABLING, ModelType.BOOLEAN, false)
        .setAllowExpression(true)
        .setDefaultValue(new ModelNode(true))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final ObjectTypeAttributeDefinition CONFIGURED_FILTER = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.FILTER, PATTERN_FILTER, ENABLING)
        .build();

    static final ObjectListAttributeDefinition CONFIGURED_FILTERS = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.FILTERS, CONFIGURED_FILTER)
        .build();

    private static final AggregateComponentDefinition<HttpServerAuthenticationMechanismFactory> AGGREGATE_HTTP_SERVER_FACTORY = AggregateComponentDefinition.create(HttpServerAuthenticationMechanismFactory.class,
            ElytronDescriptionConstants.AGGREGATE_HTTP_SERVER_FACTORY, ElytronDescriptionConstants.HTTP_SERVER_FACTORIES, HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY,
            (HttpServerAuthenticationMechanismFactory[] n) -> new AggregateServerMechanismFactory(n));

    static ResourceDefinition getSecurityDomainHttpServerConfiguration() {
        AttributeDefinition[] attributes = new AttributeDefinition[] { SECURITY_DOMAIN, HTTP_SERVER_FACTORY_FOR_CONFIG };
        AbstractAddStepHandler add = new TrivialAddHandler<SecurityDomainHttpConfiguration>(HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY, SecurityDomainHttpConfiguration.class, attributes) {

            @Override
            protected ValueSupplier<SecurityDomainHttpConfiguration> getValueSupplier(
                    ServiceBuilder<SecurityDomainHttpConfiguration> serviceBuilder, OperationContext context, ModelNode model)
                    throws OperationFailedException {

                final InjectedValue<SecurityDomain> securityDomainInjector = new InjectedValue<SecurityDomain>();
                final InjectedValue<HttpServerAuthenticationMechanismFactory> mechanismFactoryInjector = new InjectedValue<HttpServerAuthenticationMechanismFactory>();

                String securityDomain = SECURITY_DOMAIN.resolveModelAttribute(context, model).asString();
                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(SECURITY_DOMAIN_CAPABILITY, securityDomain), SecurityDomain.class),
                        SecurityDomain.class, securityDomainInjector);

                String httpServerFactory = HTTP_SERVER_FACTORY_FOR_CONFIG.resolveModelAttribute(context, model).asString();
                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(HTTP_SERVER_FACTORY_CAPABILITY, httpServerFactory), HttpServerAuthenticationMechanismFactory.class),
                        HttpServerAuthenticationMechanismFactory.class, mechanismFactoryInjector);

                return () -> new SecurityDomainHttpConfiguration(securityDomainInjector.getValue(), mechanismFactoryInjector.getValue());
            }
        };

        return wrapConfiguration(new TrivialResourceDefinition<>(ElytronDescriptionConstants.HTTP_SERVER_AUTHENITCATION, HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY,
                SecurityDomainHttpConfiguration.class, add, attributes));
    }

    static AggregateComponentDefinition<HttpServerAuthenticationMechanismFactory> getRawAggregateHttpServerFactoryDefintion() {
        return AGGREGATE_HTTP_SERVER_FACTORY;
    }

    static ResourceDefinition getAggregateHttpServerFactoryDefintion() {
        return wrapFactory(AGGREGATE_HTTP_SERVER_FACTORY);
    }

    static ResourceDefinition getConfigurableHttpServerFactoryDefinition() {
        AttributeDefinition[] attributes = new AttributeDefinition[] { HTTP_SERVER_FACTORY_FOR_FACTORY, CONFIGURED_FILTERS, PROPERTIES };
        AbstractAddStepHandler add = new TrivialAddHandler<HttpServerAuthenticationMechanismFactory>(HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY, HttpServerAuthenticationMechanismFactory.class, attributes) {

            @Override
            protected ValueSupplier<HttpServerAuthenticationMechanismFactory> getValueSupplier(
                    ServiceBuilder<HttpServerAuthenticationMechanismFactory> serviceBuilder, OperationContext context,
                    ModelNode model) throws OperationFailedException {

                final InjectedValue<HttpServerAuthenticationMechanismFactory> factoryInjector = new InjectedValue<HttpServerAuthenticationMechanismFactory>();

                String httpServerFactory = HTTP_SERVER_FACTORY_FOR_CONFIG.resolveModelAttribute(context, model).asString();
                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(HTTP_SERVER_FACTORY_CAPABILITY, httpServerFactory), HttpServerAuthenticationMechanismFactory.class),
                        HttpServerAuthenticationMechanismFactory.class, factoryInjector);

                final Predicate<String> finalFilter;
                if (model.hasDefined(ElytronDescriptionConstants.FILTERS)) {
                    Predicate<String> filter = null;
                    List<ModelNode> nodes = model.require(ElytronDescriptionConstants.FILTERS).asList();
                    for (ModelNode current : nodes) {
                        Predicate<String> currentFilter = (String s) -> true;
                        String patternFilter = asStringIfDefined(context, PATTERN_FILTER, current);
                        if (patternFilter != null) {
                            final Pattern pattern = Pattern.compile(patternFilter);
                            currentFilter = (String s) -> pattern.matcher(s).find();
                        }

                        currentFilter = ENABLING.resolveModelAttribute(context, current).asBoolean() ? currentFilter : currentFilter.negate();
                        filter = filter == null ? currentFilter : filter.or(currentFilter);
                    }
                    finalFilter = filter;
                } else {
                    finalFilter = null;
                }

                final Map<String, String> propertiesMap;
                final ModelNode properties = PROPERTIES.resolveModelAttribute(context, model);
                if (properties.isDefined()) {
                    propertiesMap = new HashMap<String, String>();
                    properties.keys().forEach((String s) -> propertiesMap.put(s, properties.require(s).asString()));
                } else {
                    propertiesMap = null;
                }

                return () -> {
                    HttpServerAuthenticationMechanismFactory factory = factoryInjector.getValue();
                    factory = finalFilter != null ? new FilterServerMechanismFactory(factory, finalFilter) : factory;
                    factory = propertiesMap != null ? new PropertiesServerMechanismFactory(factoryInjector.getValue(), propertiesMap) : factory;

                    return factory;
                };
            }
        };

        return wrapFactory(new TrivialResourceDefinition<>(ElytronDescriptionConstants.CONFIGURABLE_HTTP_SERVER_FACTORY,
                HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY, HttpServerAuthenticationMechanismFactory.class, add, attributes));
    }

    static ResourceDefinition getProviderHttpServerFactoryDefinition() {
        AttributeDefinition[] attributes = new AttributeDefinition[] { PROVIDER_LOADER };
        AbstractAddStepHandler add = new TrivialAddHandler<HttpServerAuthenticationMechanismFactory>(HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY, HttpServerAuthenticationMechanismFactory.class, attributes) {

            @Override
            protected ValueSupplier<HttpServerAuthenticationMechanismFactory> getValueSupplier(
                    ServiceBuilder<HttpServerAuthenticationMechanismFactory> serviceBuilder, OperationContext context,
                    ModelNode model) throws OperationFailedException {

                String provider = asStringIfDefined(context, PROVIDER_LOADER, model);
                final Supplier<Provider[]> providerSupplier;
                if (provider != null) {
                    final InjectedValue<Provider[]> providersInjector = new InjectedValue<Provider[]>();
                    serviceBuilder.addDependency(context.getCapabilityServiceName(
                            buildDynamicCapabilityName(PROVIDERS_CAPABILITY, provider), Provider[].class),
                            Provider[].class, providersInjector);
                    providerSupplier = providersInjector::getValue;
                } else {
                    providerSupplier = Security::getProviders;
                }

                return () -> new SecurityProviderServerMechanismFactory(providerSupplier);
            }

        };

        return wrapFactory(new TrivialResourceDefinition<HttpServerAuthenticationMechanismFactory>(ElytronDescriptionConstants.PROVIDER_HTTP_SERVER_FACTORY, HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY,
                HttpServerAuthenticationMechanismFactory.class, add, attributes));
    }

    static ResourceDefinition getServiceLoaderServerFactoryDefinition() {
        AttributeDefinition[] attributes = new AttributeDefinition[] { MODULE, SLOT };
        AbstractAddStepHandler add = new TrivialAddHandler<HttpServerAuthenticationMechanismFactory>(HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY, HttpServerAuthenticationMechanismFactory.class, attributes) {

            @Override
            protected ValueSupplier<HttpServerAuthenticationMechanismFactory> getValueSupplier(
                    ServiceBuilder<HttpServerAuthenticationMechanismFactory> serviceBuilder, OperationContext context,
                    ModelNode model) throws OperationFailedException {
                final String module = asStringIfDefined(context, MODULE, model);
                final String slot = asStringIfDefined(context, SLOT, model);

                return () -> {
                    try {
                        ClassLoader classLoader = doPrivileged((PrivilegedExceptionAction<ClassLoader>) () -> resolveClassLoader(module, slot));

                        return new ServiceLoaderServerMechanismFactory(classLoader);
                    } catch (Exception e) {
                        throw new StartException(e);
                    }
                };

            }
        };

        return wrapFactory(new TrivialResourceDefinition<HttpServerAuthenticationMechanismFactory>(ElytronDescriptionConstants.SERVICE_LOADER_HTTP_SERVER_FACTORY, HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY,
                HttpServerAuthenticationMechanismFactory.class, add, attributes));
    }

    private static ResourceDefinition wrapConfiguration(ResourceDefinition resourceDefinition) {
        return AvailableMechanismsRuntimeResource.wrap(
                resourceDefinition,
                (context) -> {
                    RuntimeCapability<Void> runtimeCapability = HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
                    ServiceName configurationName = runtimeCapability.getCapabilityServiceName(SecurityDomainHttpConfiguration.class);

                    ServiceRegistry registry = context.getServiceRegistry(false);
                    ServiceController<SecurityDomainHttpConfiguration> serviceContainer = getRequiredService(registry, configurationName, SecurityDomainHttpConfiguration.class);
                    if (serviceContainer.getState() != State.UP) {
                        return null;
                    }
                    return serviceContainer.getValue().getMechanismFactory().getMechanismNames(Collections.emptyMap());
                });
    }

    private static ResourceDefinition wrapFactory(ResourceDefinition resourceDefinition) {
        return AvailableMechanismsRuntimeResource.wrap(
                resourceDefinition,
                (context) -> {
                    RuntimeCapability<Void> runtimeCapability = HTTP_SERVER_FACTORY_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
                    ServiceName httpServerFactoryName = runtimeCapability.getCapabilityServiceName(HttpServerAuthenticationMechanismFactory.class);

                    ServiceRegistry registry = context.getServiceRegistry(false);
                    ServiceController<HttpServerAuthenticationMechanismFactory> serviceContainer = getRequiredService(registry, httpServerFactoryName, HttpServerAuthenticationMechanismFactory.class);
                    if (serviceContainer.getState() != State.UP) {
                        return null;
                    }
                    return serviceContainer.getValue().getMechanismNames(Collections.emptyMap());
                });
    }

}
