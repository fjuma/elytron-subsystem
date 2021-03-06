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

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.msc.service.ServiceName;

/**
 * A trivial {@link ResourceDefinition}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class TrivialResourceDefinition<T> extends SimpleResourceDefinition {

    private final String pathKey;
    private final RuntimeCapability<?> runtimeCapability;
    private final Class<T> serviceType;
    private final AttributeDefinition[] attributes;

    TrivialResourceDefinition(String pathKey, RuntimeCapability<?> runtimeCapability, Class<T> serviceType, AbstractAddStepHandler add, AttributeDefinition ... attributes) {
        super(new Parameters(PathElement.pathElement(pathKey),
                ElytronExtension.getResourceDescriptionResolver(pathKey))
            .setAddHandler(add)
            .setRemoveHandler(new SingleCapabilityServiceRemoveHandler<T>(add, runtimeCapability, serviceType))
            .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
            .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));

        this.pathKey = pathKey;
        this.runtimeCapability = runtimeCapability;
        this.serviceType = serviceType;
        this.attributes = attributes;
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
         if (attributes != null && attributes.length > 0) {
             WriteAttributeHandler write = new WriteAttributeHandler(pathKey, attributes);
             for (AttributeDefinition current : attributes) {
                 resourceRegistration.registerReadWriteAttribute(current, null, write);
             }
         }
    }

    @Override
    public void registerCapabilities(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerCapability(runtimeCapability);
    }

    private class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler(String parentName, AttributeDefinition ... attributes) {
            super(parentName, attributes);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return runtimeCapability.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(serviceType);
        }
    }

}
