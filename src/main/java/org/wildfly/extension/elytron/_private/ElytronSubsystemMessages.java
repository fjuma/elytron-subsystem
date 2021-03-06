/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.extension.elytron._private;

import static org.jboss.logging.Logger.Level.INFO;

import java.security.KeyStore;
import java.security.Provider;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartException;
import org.wildfly.extension.elytron.Configurable;

/**
 * Messages for the Elytron subsystem.
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "WFLYELY", length = 5)
public interface ElytronSubsystemMessages extends BasicLogger {

    /**
     * A root logger with the category of the package name.
     */
    ElytronSubsystemMessages ROOT_LOGGER = Logger.getMessageLogger(ElytronSubsystemMessages.class, "org.wildfly.extension.elytron");

    @LogMessage(level = INFO)
    @Message(id = 1, value = "I am Elytron, nice to meet you.")
    void iAmElytron();

    /**
     * {@link OperationFailedException} if the same realm is injected multiple times for a single domain.
     *
     * @param realmName - the name of the {@link SecurityRealm} being injected.
     * @param domainName - the name of the {@link SecurityDomain} the realm is being injected for.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 2, value = "Can not inject the same realm '%s' in a single security domain '%s'.")
    OperationFailedException duplicateRealmInjection(final String realmName, final String domainName);

    /**
     * An {@link IllegalArgumentException} if the supplied operation did not contain an address with a value for the required key.
     *
     * @param key - the required key in the address of the operation.
     * @return The {@link IllegalArgumentException} for the error.
     */
    @Message(id = 3, value = "The operation did not contain an address with a value for '%s'.")
    IllegalArgumentException operationAddressMissingKey(final String key);

    /**
     * A {@link StartException} if it is not possible to initialise the {@link Service}.
     *
     * @param cause the cause of the failure.
     * @return The {@link StartException} for the error.
     */
    @Message(id = 4, value = "Unable to start the service.")
    StartException unableToStartService(@Cause Exception cause);

    /**
     * An {@link OperationFailedException} if it is not possible to access the {@link KeyStore} at RUNTIME.
     *
     * @param cause the underlying cause of the failure
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 5, value = "Unable to access KeyStore to complete the requested operation.")
    OperationFailedException unableToAccessKeyStore(@Cause Exception cause);

    /**
     * An {@link OperationFailedException} for operations that are unable to populate the result.
     *
     * @param cause the underlying cause of the failure.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 6, value = "Unable to populate result.")
    OperationFailedException unableToPopulateResult(@Cause Exception cause);

    /**
     * An {@link OperationFailedException} where an operation can not proceed as it's required service is not UP.
     *
     * @param serviceName the name of the service that is required.
     * @param state the actual state of the service.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 7, value = "The required service '%s' is not UP, it is currently '%s'.")
    OperationFailedException requiredServiceNotUp(ServiceName serviceName, State state);

    /**
     * An {@link OperationFailedException} where the name of the operation does not match the expected names.
     *
     * @param actualName the operation name contained within the request.
     * @param expectedNames the expected operation names.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 8, value = "Invalid operation name '%s', expected one of '%s'")
    OperationFailedException invalidOperationName(String actualName, String... expectedNames);

    /**
     * An {@link OperationFailedException} where an operation can not be completed.
     *
     * @param cause the underlying cause of the failure.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 9, value = "Unable to complete operation.")
    OperationFailedException unableToCompleteOperation(@Cause Throwable cause);

    /**
     * An {@link OperationFailedException} where this an attempt to save a KeyStore without a File defined.
     *
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 10, value = "Unable to complete operation.")
    OperationFailedException cantSaveWithoutFile();

    /**
     * A {@link StartException} for when provider registration fails due to an existing registration.
     *
     * @param name the name of the provider registration failed for.
     * @return The {@link StartException} for the error.
     */
    @Message(id = 11, value = "A Provider is already registered for '%s'")
    StartException providerAlreadyRegisteres(String name);

    /**
     * A {@link StartException} where a service can not identify a suitable {@link Provider}
     *
     * @param type the type being searched for.
     * @return The {@link StartException} for the error.
     */
    @Message(id = 12, value = "No suitable provider found for type '%s'")
    StartException noSuitableProvider(String type);

    /**
     * A {@link OperationFailedException} for when an attempt is made to define a domain that has a default realm specified that
     * it does not actually reference.
     *
     * @param defaultRealm the name of the default_realm specified.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 13, value = "The default_realm '%s' is not in the list or realms referenced by this domain.")
    OperationFailedException defaultRealmNotReferenced(String defaultRealm);

    /**
     * A {@link StartException} for when the properties file backed realm can not be started due to problems loading the
     * properties files.
     *
     * @param cause the underlying cause of the error.
     * @return The {@link StartException} for the error.
     */
    @Message(id = 14, value = "Unable to load the properties files required to start the properties file backed realm.")
    StartException unableToLoadPropertiesFiles(@Cause Exception cause);

    /**
     * A {@link StartException} where a custom component has been defined with configuration but does not implement
     * the {@link Configurable} interface.
     *
     * @param className the class name of the custom component implementation being loaded.
     * @return The {@link StartException} for the error.
     */
    @Message(id = 15, value = "The custom component implementation '%s' doe not implement 'org.wildfly.extension.elytron.Configurable' however configuration has been supplied.")
    StartException componentNotConfigurable(final String className);

    /**
     * An {@link OperationFailedException} where validation of a specified regular expression has failed.
     *
     * @param pattern the regular expression that failed validation.
     * @param cause the reported {@link Exception} during validation.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 16, value = "The supplied regular expression '%s' is invalid.")
    OperationFailedException invalidRegularExpression(String pattern, @Cause Exception cause);

    @Message(id = 17, value = "Security realm [%s] is not modifiable.")
    OperationFailedException realmNotModifiable(ServiceName serviceName);
}
