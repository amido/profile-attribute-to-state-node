/*
 *
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 David Luna.
 *
 *  Chandra Dhulipala - June 2018 - Modified the node type and customised for displaying messages
 */

package org.forgerock.am;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.RequiredValueValidator;

import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.utils.CrestQuery;
import org.forgerock.util.i18n.PreferredLocales;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;

import static javax.security.auth.callback.TextOutputCallback.ERROR;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

/**
 * A node that copies a value from a user's profile attributes into a value in their authentication shared state.
 *
 * @author chandradhulipala
 */
@Node.Metadata(outcomeProvider = ProfileAttributeToStateNode.OutcomeProvider.class,
               configClass = ProfileAttributeToStateNode.Config.class)
public class ProfileAttributeToStateNode extends AbstractDecisionNode {

    private final static String DEBUG_FILE = "ProfileAttributeToStateNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    private final ProfileAttributeToStateNode.Config config;
    private final CoreWrapper coreWrapper;

    private final static String SUCCESS = "success";
    private final static String FAILURE = "failure";

    /**
     * Configuration for the node.
     */
   public interface Config {
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default Map<String, String> keys() { return Collections.emptyMap(); }

        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        default SelectType selectType() { return SelectType.SelectFirst; }
    }

    /**
     * Create the node.
     *
     * @param config The service config.
     * @param coreWrapper The coreWrapper.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ProfileAttributeToStateNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
//        verifyUsernameAndRealm(context);

        JsonValue sharedState = context.sharedState.copy();

        if(context.hasCallbacks()) {
            debug.message("[" + DEBUG_FILE + "]: " + "has callbacks");
            return goTo(FAILURE).build();
        }

        for (Map.Entry<String, String> entry : config.keys().entrySet()) {
            Set value = null;
            String storageLocation = entry.getValue();

            try {
                value = getValueForKeyFromProfile(entry.getKey(), context);
                if (value == null) {
                    debug.message("[" + DEBUG_FILE + "]: " + "Invalid input provided" + entry.getKey());
                    List<Callback> callbacks = new ArrayList<Callback>(1);
                    String errMsg = "Please enter valid credentials";
                    TextOutputCallback textCb = new TextOutputCallback(ERROR, errMsg);
                    callbacks = ImmutableList.of(textCb);
                    return send(ImmutableList.copyOf(callbacks)).build();
                }
            } catch (IdRepoException | SSOException e) {
                debug.error("[" + DEBUG_FILE + "]: " + "Error retrieving value from user's profile:::::: " + e);
            }

            Object selectedValue;

            switch (config.selectType()) {
                case SelectFirst:
                    if (!value.iterator().hasNext()) {
                        selectedValue = null;
                    } else {
                        selectedValue = value.iterator().next();
                    }
                    break;
                case SelectAsString:
                    selectedValue = value.toString();
                    break;
                case SelectExact:
                default:
                    selectedValue = value;
                    break;
            }
            sharedState.put(storageLocation, selectedValue);
        }

        return goTo(SUCCESS).replaceSharedState(sharedState).build();
    }

    private void verifyUsernameAndRealm(TreeContext context) throws NodeProcessException {
        if (context.sharedState.get(USERNAME).isNull() || context.sharedState.get(REALM).isNull()) {
            throw new NodeProcessException("Username and realm must be selected.");
        }
    }

    private Set getValueForKeyFromProfile(String key, TreeContext context) throws IdRepoException, SSOException {
//        AMIdentity user = getIdentity(context.sharedState.get(USERNAME).asString(),
//                context.sharedState.get(REALM).asString());

        final String INPUT = "mail";
        Set<String> userAttributes = new HashSet<>();
        userAttributes.add("uid");
        userAttributes.add("mail");
        AMIdentity user = IdUtils.getIdentity(context.sharedState.get(INPUT).asString(), context.sharedState.get(REALM).asString(), userAttributes);

        return user != null ? user.getAttribute(key) : null;
    }

    private AMIdentity getIdentity(String username, String realm) throws IdRepoException, SSOException {
        AMIdentityRepository idrepo = coreWrapper.getAMIdentityRepository(
                coreWrapper.convertRealmNameToOrgName(realm));
        IdSearchControl idSearchControl = new IdSearchControl();
        idSearchControl.setAllReturnAttributes(true);

        IdSearchResults idSearchResults = idrepo.searchIdentities(IdType.USER,
                new CrestQuery(username), idSearchControl);
        return (AMIdentity) idSearchResults.getSearchResults().iterator().next();
    }

    /**
     * Enum representing various selecting approaches.
     */
    public enum SelectType {
        SelectExact,
        SelectFirst,
        SelectAsString
    }

    private Action.ActionBuilder goTo(String outcome) {
        return Action.goTo(outcome);
    }

    static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        private static final String BUNDLE = ProfileAttributeToStateNode.class.getName().replace(".", "/");

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(SUCCESS, bundle.getString("success")),
                    new Outcome(FAILURE, bundle.getString("failure")));
        }
    }


}