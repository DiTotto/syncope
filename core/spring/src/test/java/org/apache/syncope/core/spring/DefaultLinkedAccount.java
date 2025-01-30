package org.apache.syncope.core.spring;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.entity.ExternalResource;
import org.apache.syncope.core.persistence.api.entity.Privilege;
import org.apache.syncope.core.persistence.api.entity.user.LAPlainAttr;
import org.apache.syncope.core.persistence.api.entity.user.LinkedAccount;
import org.apache.syncope.core.persistence.api.entity.user.User;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public class DefaultLinkedAccount implements LinkedAccount {

    private String username;

    @Override
    public String getConnObjectKeyValue() {
        return "";
    }

    @Override
    public void setConnObjectKeyValue(String connObjectKeyValue) {

    }

    @Override
    public User getOwner() {
        return null;
    }

    @Override
    public void setOwner(User owner) {

    }

    @Override
    public ExternalResource getResource() {
        return null;
    }

    @Override
    public void setResource(ExternalResource resource) {

    }

    @Override
    public boolean add(Privilege privilege) {
        return false;
    }

    @Override
    public Set<? extends Privilege> getPrivileges() {
        return Set.of();
    }

    @Override
    public boolean add(LAPlainAttr attr) {
        return false;
    }

    @Override
    public boolean remove(LAPlainAttr attr) {
        return false;
    }

    @Override
    public Optional<? extends LAPlainAttr> getPlainAttr(String plainSchema) {
        return Optional.empty();
    }

    @Override
    public List<? extends LAPlainAttr> getPlainAttrs() {
        return List.of();
    }

    @Override
    public String getKey() {
        return "";
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public CipherAlgorithm getCipherAlgorithm() {
        return null;
    }

    @Override
    public boolean canDecodeSecrets() {
        return false;
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public void setEncodedPassword(String password, CipherAlgorithm cipherAlgoritm) {

    }

    @Override
    public void setPassword(String password) {

    }

    @Override
    public void setCipherAlgorithm(CipherAlgorithm cipherAlgorithm) {

    }

    @Override
    public Boolean isSuspended() {
        return null;
    }

    @Override
    public void setSuspended(Boolean suspended) {

    }
}
