/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.workflow.java;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.syncope.common.lib.request.PasswordPatch;
import org.apache.syncope.common.lib.request.UserCR;
import org.apache.syncope.common.lib.request.UserUR;
import org.apache.syncope.common.lib.types.EntityViolationType;
import org.apache.syncope.common.lib.types.IdRepoEntitlement;
import org.apache.syncope.common.lib.types.ResourceOperation;
import org.apache.syncope.core.persistence.api.attrvalue.validation.InvalidEntityException;
import org.apache.syncope.core.persistence.api.dao.RealmDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.Entity;
import org.apache.syncope.core.persistence.api.entity.EntityFactory;
import org.apache.syncope.core.persistence.api.entity.ExternalResource;
import org.apache.syncope.core.persistence.api.entity.Implementation;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.policy.AccountPolicy;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.provisioning.api.PropagationByResource;
import org.apache.syncope.core.provisioning.api.UserWorkflowResult;
import org.apache.syncope.core.provisioning.api.data.UserDataBinder;
import org.apache.syncope.core.provisioning.api.rules.AccountRule;
import org.apache.syncope.core.provisioning.api.rules.PasswordRule;
import org.apache.syncope.core.spring.implementation.ImplementationManager;
import org.apache.syncope.core.spring.policy.AccountPolicyException;
import org.apache.syncope.core.spring.policy.PasswordPolicyException;
import org.apache.syncope.core.spring.security.AuthContextUtils;
import org.apache.syncope.core.spring.security.Encryptor;
import org.apache.syncope.core.spring.security.SecurityProperties;
import org.apache.syncope.core.workflow.api.UserWorkflowAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = { Throwable.class })
public abstract class AbstractUserWorkflowAdapter extends AbstractWorkflowAdapter implements UserWorkflowAdapter {

    protected static final Logger LOG = LoggerFactory.getLogger(UserWorkflowAdapter.class);

    protected final UserDataBinder dataBinder;

    protected final UserDAO userDAO;

    protected final RealmDAO realmDAO;

    protected final EntityFactory entityFactory;

    protected final SecurityProperties securityProperties;

    protected final Map<String, AccountRule> perContextAccountRules = new ConcurrentHashMap<>();

    protected final Map<String, PasswordRule> perContextPasswordRules = new ConcurrentHashMap<>();

    public AbstractUserWorkflowAdapter(
            final UserDataBinder dataBinder,
            final UserDAO userDAO,
            final RealmDAO realmDAO,
            final EntityFactory entityFactory,
            final SecurityProperties securityProperties) {

        this.dataBinder = dataBinder;
        this.userDAO = userDAO;
        this.realmDAO = realmDAO;
        this.entityFactory = entityFactory;
        this.securityProperties = securityProperties;
    }

    @Override
    public String getPrefix() {
        return null;
    }

    protected List<AccountPolicy> getAccountPolicies(final User user) {
        List<AccountPolicy> policies = new ArrayList<>();

        // add resource policies
        userDAO.findAllResources(user).stream().
                map(ExternalResource::getAccountPolicy).
                filter(Objects::nonNull).
                forEach(policies::add);

        // add realm policies
        realmDAO.findAncestors(user.getRealm()).stream().
                map(Realm::getAccountPolicy).
                filter(Objects::nonNull).
                forEach(policies::add);

        return policies;
    }

    protected List<AccountRule> getAccountRules(final AccountPolicy policy) {
        List<AccountRule> result = new ArrayList<>();

        for (Implementation impl : policy.getRules()) {
            try {
                ImplementationManager.buildAccountRule(
                        impl,
                        () -> perContextAccountRules.get(impl.getKey()),
                        instance -> perContextAccountRules.put(impl.getKey(), instance)).
                        ifPresent(result::add);
            } catch (Exception e) {
                LOG.warn("While building {}", impl, e);
            }
        }

        return result;
    }

    protected List<PasswordPolicy> getPasswordPolicies(final User user) {
        List<PasswordPolicy> policies = new ArrayList<>();

        // add resource policies
        userDAO.findAllResources(user).
                forEach(resource -> Optional.ofNullable(resource.getPasswordPolicy()).
                filter(p -> !policies.contains(p)).
                ifPresent(policies::add));

        // add realm policies
        realmDAO.findAncestors(user.getRealm()).
                forEach(realm -> Optional.ofNullable(realm.getPasswordPolicy()).
                filter(p -> !policies.contains(p)).
                ifPresent(policies::add));

        return policies;
    }

    protected List<PasswordRule> getPasswordRules(final PasswordPolicy policy) {
        List<PasswordRule> result = new ArrayList<>();

        for (Implementation impl : policy.getRules()) {
            try {
                ImplementationManager.buildPasswordRule(
                        impl,
                        () -> perContextPasswordRules.get(impl.getKey()),
                        instance -> perContextPasswordRules.put(impl.getKey(), instance)).
                        ifPresent(result::add);
            } catch (Exception e) {
                LOG.warn("While building {}", impl, e);
            }
        }

        return result;
    }

    protected Pair<Boolean, Boolean> enforcePolicies(
            final User user,
            final boolean disablePwdPolicyCheck,
            final String clearPassword) {

        if (!disablePwdPolicyCheck) {
            // ------------------------------
            // Verify password policies
            // ------------------------------
            LOG.debug("Password Policy enforcement");

            try {
                int maxPPSpecHistory = 0;
                for (PasswordPolicy policy : getPasswordPolicies(user)) {
                    if (clearPassword == null && !policy.isAllowNullPassword()) {
                        throw new PasswordPolicyException("Password mandatory");
                    }

                    getPasswordRules(policy).forEach(rule -> {
                        rule.enforce(user, clearPassword);

                        user.getLinkedAccounts().stream().
                                filter(account -> account.getPassword() != null).
                                forEach(rule::enforce);
                    });

                    boolean matching = false;
                    if (policy.getHistoryLength() > 0) {
                        List<String> pwdHistory = user.getPasswordHistory();
                        matching = pwdHistory.subList(policy.getHistoryLength() >= pwdHistory.size()
                                ? 0
                                : pwdHistory.size() - policy.getHistoryLength(), pwdHistory.size()).stream().
                                map(old -> Encryptor.getInstance().verify(
                                clearPassword, user.getCipherAlgorithm(), old)).
                                reduce(matching, (accumulator, item) -> accumulator | item);
                    }
                    if (matching) {
                        throw new PasswordPolicyException("Password value was used in the past: not allowed");
                    }

                    if (policy.getHistoryLength() > maxPPSpecHistory) {
                        maxPPSpecHistory = policy.getHistoryLength();
                    }
                }

                // update user's password history with encrypted password
                if (maxPPSpecHistory > 0
                        && user.getPassword() != null
                        && !user.getPasswordHistory().contains(user.getPassword())) {

                    user.addToPasswordHistory(user.getPassword());
                }
                // keep only the last maxPPSpecHistory items in user's password history
                if (maxPPSpecHistory < user.getPasswordHistory().size()) {
                    user.removeOldestEntriesFromPasswordHistory(user.getPasswordHistory().size() - maxPPSpecHistory);
                }
            } catch (InvalidEntityException e) {
                throw e;
            } catch (Exception e) {
                LOG.error("Invalid password for {}", user, e);
                throw new InvalidEntityException(User.class, EntityViolationType.InvalidPassword, e.getMessage());
            }
        }

        // ------------------------------
        // Verify account policies
        // ------------------------------
        LOG.debug("Account Policy enforcement");

        boolean suspend = false;
        boolean propagateSuspension = false;
        try {
            if (user.getUsername() == null) {
                throw new AccountPolicyException("Null username");
            }

            if (securityProperties.getAdminUser().equals(user.getUsername())
                    || securityProperties.getAnonymousUser().equals(user.getUsername())) {

                throw new AccountPolicyException("Not allowed: " + user.getUsername());
            }

            List<AccountPolicy> accountPolicies = getAccountPolicies(user);
            if (accountPolicies.isEmpty()) {
                if (!Entity.ID_PATTERN.matcher(user.getUsername()).matches()) {
                    throw new AccountPolicyException("Character(s) not allowed: " + user.getUsername());
                }
                user.getLinkedAccounts().stream().
                        filter(account -> account.getUsername() != null).
                        forEach(account -> {
                            if (!Entity.ID_PATTERN.matcher(account.getUsername()).matches()) {
                                throw new AccountPolicyException("Character(s) not allowed: " + account.getUsername());
                            }
                        });
            } else {
                for (AccountPolicy policy : accountPolicies) {
                    getAccountRules(policy).forEach(rule -> {
                        rule.enforce(user);

                        user.getLinkedAccounts().stream().
                                filter(account -> account.getUsername() != null).
                                forEach(rule::enforce);
                    });

                    suspend |= user.getFailedLogins() != null && policy.getMaxAuthenticationAttempts() > 0
                            && user.getFailedLogins() > policy.getMaxAuthenticationAttempts() && !user.isSuspended();
                    propagateSuspension |= policy.isPropagateSuspension();
                }
            }
        } catch (InvalidEntityException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("Invalid username for {}", user, e);
            throw new InvalidEntityException(User.class, EntityViolationType.InvalidUsername, e.getMessage());
        }

        return Pair.of(suspend, propagateSuspension);
    }

    @Override
    public UserWorkflowResult<Pair<String, Boolean>> create(
            final UserCR userCR, final String creator, final String context) {

        return create(userCR, false, null, creator, context);
    }

    protected abstract UserWorkflowResult<Pair<String, Boolean>> doCreate(
            UserCR userCR, boolean disablePwdPolicyCheck, Boolean enabled, String creator, String context);

    @Override
    public UserWorkflowResult<Pair<String, Boolean>> create(
            final UserCR userCR,
            final boolean disablePwdPolicyCheck,
            final Boolean enabled,
            final String creator,
            final String context) {

        UserWorkflowResult<Pair<String, Boolean>> result =
                doCreate(userCR, disablePwdPolicyCheck, enabled, creator, context);

        // enforce password and account policies
        User user = userDAO.find(result.getResult().getKey());
        enforcePolicies(user, disablePwdPolicyCheck, disablePwdPolicyCheck ? null : userCR.getPassword());
        userDAO.save(user);

        return result;
    }

    protected abstract UserWorkflowResult<String> doActivate(User user, String token, String updater, String context);

    @Override
    public UserWorkflowResult<String> activate(
            final String key, final String token, final String updater, final String context) {

        return doActivate(userDAO.authFind(key), token, updater, context);
    }

    protected abstract UserWorkflowResult<Pair<UserUR, Boolean>> doUpdate(
            User user, UserUR userUR, String updater, String context);

    @Override
    public UserWorkflowResult<Pair<UserUR, Boolean>> update(
            final UserUR userUR, final String updater, final String context) {

        User user = userDAO.find(userUR.getKey());

        UserWorkflowResult<Pair<UserUR, Boolean>> result;
        // skip actual workflow operations in case only password change on resources was requested
        if (userUR.isEmptyButPassword() && !userUR.getPassword().isOnSyncope()) {
            PropagationByResource<String> propByRes = new PropagationByResource<>();
            userDAO.findAllResources(user).stream().
                    filter(resource -> userUR.getPassword().getResources().contains(resource.getKey())).
                    forEach(resource -> propByRes.add(ResourceOperation.UPDATE, resource.getKey()));

            PropagationByResource<Pair<String, String>> propByLinkedAccount = new PropagationByResource<>();
            user.getLinkedAccounts().stream().
                    filter(account -> userUR.getPassword().getResources().contains(account.getResource().getKey())).
                    forEach(account -> propByLinkedAccount.add(
                    ResourceOperation.UPDATE,
                    Pair.of(account.getResource().getKey(), account.getConnObjectKeyValue())));

            result = new UserWorkflowResult<>(
                    Pair.of(userUR, !user.isSuspended()), propByRes, propByLinkedAccount, "update");
        } else {
            result = doUpdate(userDAO.authFind(userUR.getKey()), userUR, updater, context);
        }

        // enforce password and account policies
        enforcePolicies(
                user,
                userUR.getPassword() == null,
                Optional.ofNullable(userUR.getPassword()).map(PasswordPatch::getValue).orElse(null));
        user = userDAO.save(user);

        if (!AuthContextUtils.getUsername().equals(user.getUsername())) {
            // ensure that requester's administration rights are still valid
            Set<String> authRealms = new HashSet<>();
            authRealms.addAll(AuthContextUtils.getAuthorizations().
                    getOrDefault(IdRepoEntitlement.USER_READ, Set.of()));
            authRealms.addAll(AuthContextUtils.getAuthorizations().
                    getOrDefault(IdRepoEntitlement.USER_UPDATE, Set.of()));
            userDAO.securityChecks(
                    authRealms,
                    user.getKey(),
                    user.getRealm().getFullPath(),
                    userDAO.findAllGroupKeys(user));
        }

        return result;
    }

    protected abstract UserWorkflowResult<String> doSuspend(User user, String updater, String context);

    @Override
    public UserWorkflowResult<String> suspend(final String key, final String updater, final String context) {
        User user = userDAO.authFind(key);

        // set suspended flag
        user.setSuspended(Boolean.TRUE);

        return doSuspend(user, updater, context);
    }

    @Override
    public Pair<UserWorkflowResult<String>, Boolean> internalSuspend(
            final String key, final String updater, final String context) {

        User user = userDAO.authFind(key);

        Pair<UserWorkflowResult<String>, Boolean> result = null;

        Pair<Boolean, Boolean> enforce = enforcePolicies(user, true, null);
        if (enforce.getKey()) {
            LOG.debug("User {} {} is over the max failed logins", user.getKey(), user.getUsername());

            // reduce failed logins number to avoid multiple request       
            user.setFailedLogins(user.getFailedLogins() - 1);

            // set suspended flag
            user.setSuspended(Boolean.TRUE);

            result = Pair.of(doSuspend(user, updater, context), enforce.getValue());
        }

        return result;
    }

    protected abstract UserWorkflowResult<String> doReactivate(User user, String updater, String context);

    @Override
    public UserWorkflowResult<String> reactivate(final String key, final String updater, final String context) {
        User user = userDAO.authFind(key);

        // reset failed logins
        user.setFailedLogins(0);

        // reset suspended flag
        user.setSuspended(Boolean.FALSE);

        return doReactivate(user, updater, context);
    }

    protected abstract void doRequestPasswordReset(User user, String updater, String context);

    @Override
    public void requestPasswordReset(final String key, final String updater, final String context) {
        doRequestPasswordReset(userDAO.authFind(key), updater, context);
    }

    protected abstract UserWorkflowResult<Pair<UserUR, Boolean>> doConfirmPasswordReset(
            User user, String token, String password, String updater, String context);

    @Override
    public UserWorkflowResult<Pair<UserUR, Boolean>> confirmPasswordReset(
            final String key, final String token, final String password, final String updater, final String context) {

        User user = userDAO.authFind(key);

        // enforce password and account policies
        enforcePolicies(user, false, password);
        user = userDAO.save(user);

        return doConfirmPasswordReset(user, token, password, updater, context);
    }

    protected abstract void doDelete(User user, String eraser, String context);

    @Override
    public void delete(final String userKey, final String eraser, final String context) {
        doDelete(userDAO.authFind(userKey), eraser, context);
    }
}
