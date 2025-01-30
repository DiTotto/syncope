package org.apache.syncope.core.spring;

import org.apache.syncope.common.lib.policy.DefaultAccountRuleConf;
import org.apache.syncope.core.persistence.api.entity.user.LinkedAccount;
import org.apache.syncope.core.spring.policy.DefaultAccountRule;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.apache.syncope.core.persistence.api.entity.user.User;

import java.util.*;

import static org.junit.Assert.*;

@RunWith(Enclosed.class)
public class DefaultAccountRuleTest {

    @RunWith(Parameterized.class)
    public static class SetConfTest {

        private final DefaultAccountRuleConf AccountConf;
        private final boolean expectedException;

        public SetConfTest(DefaultAccountRuleConf AccountConf, boolean expectedException) {
            this.AccountConf = AccountConf;
            this.expectedException = expectedException;
        }

        @Parameterized.Parameters()
        public static Collection<Object[]> data() {
            DefaultAccountRuleConf validConf = new DefaultAccountRuleConf();
            validConf.setAllLowerCase(true);
            validConf.setMinLength(7);
            validConf.setMaxLength(15);
            validConf.setName("validAccount");


            DefaultAccountRuleConf invalidConf1 = new DefaultAccountRuleConf();
            invalidConf1.setMinLength(15);
            invalidConf1.setMaxLength(7);


            DefaultAccountRuleConf invalidConf2 = new DefaultAccountRuleConf();
            invalidConf2.setMinLength(5);
            invalidConf2.setMaxLength(10);
            invalidConf2.getWordsNotPermitted().add("word1");
            invalidConf2.getWordsNotPermitted().add("word2");
            invalidConf2.setName("word2");

            return Arrays.asList(new Object[][]{
                    {validConf, false},
                    {invalidConf1, false}, //true
                    {invalidConf2, false}, //true
                    {null, true}
            });
        }

        @Test
        public void testSetConf() {
            DefaultAccountRule defaultAccountRule = new DefaultAccountRule();
            try{
                defaultAccountRule.setConf(AccountConf);
                //assertFalse(expectedException);
                if(expectedException)
                    fail("Expected IllegalArgumentException but no exception was thrown");
            } catch (IllegalArgumentException | NullPointerException e) {
                assertTrue(expectedException);
            }
        }
    }


    @RunWith(Parameterized.class)
    public static class EnforceTest1{

        private final User user;
        private final boolean expectedException;
        private final DefaultAccountRuleConf conf;

        public EnforceTest1(User user, DefaultAccountRuleConf conf, boolean expectedException){
            this.user = user;
            this.expectedException = expectedException;
            this.conf = conf;
        }

        @Parameterized.Parameters()
        public static Collection<Object[]> data(){

            DefaultAccountRuleConf validConf = new DefaultAccountRuleConf();
            validConf.getWordsNotPermitted().add("fascio");

            DefaultUser validUser = new DefaultUser();
            validUser.setUsername("validUser");


            User invalidUser1 = new DefaultUser();
            invalidUser1.setUsername("fascio");

            User invalidUser2 = new DefaultUser();
            invalidUser2.setUsername("fascio is a bad word");

            User invalidUser3 = new DefaultUser();
            invalidUser2.setUsername("");

            return Arrays.asList(new Object[][]{
                {validUser, validConf, false},
                {invalidUser1, validConf, true},
                {invalidUser2, validConf, true},
                {invalidUser3, validConf, true},
                {null, validConf, true}
            });
        }

        @Test
        public void testEnforce(){
            DefaultAccountRule defaultAccountRule = new DefaultAccountRule();
            defaultAccountRule.setConf(conf);
            try{
                defaultAccountRule.enforce(user);
                //assertFalse(expectedException);
                if(expectedException)
                    fail("Expected AccountPolicyException but no exception was thrown");
            } catch (Exception e) {
                assertTrue(expectedException);
            }
        }
    }

    @RunWith(Parameterized.class)
    public static class EnforceTest2{

        private final LinkedAccount account;
        private final boolean expectedException;
        private final DefaultAccountRuleConf conf;

        public EnforceTest2(DefaultLinkedAccount account, DefaultAccountRuleConf conf, boolean expectedException){
            this.account = account;
            this.expectedException = expectedException;
            this.conf = conf;
        }

        @Parameterized.Parameters()
        public static Collection<Object[]> data(){

            DefaultAccountRuleConf validConf = new DefaultAccountRuleConf();
            validConf.getWordsNotPermitted().add("fascio");

            DefaultLinkedAccount validAccount = new DefaultLinkedAccount();
            validAccount.setUsername("validUser");


            DefaultLinkedAccount invalidAccount1 = new DefaultLinkedAccount();
            invalidAccount1.setUsername("fascio");

            DefaultLinkedAccount invalidAccount2 = new DefaultLinkedAccount();
            invalidAccount2.setUsername("fascio is a bad word");


            return Arrays.asList(new Object[][]{
                    {validAccount, validConf, false},
                    {invalidAccount1, validConf, true},
                    {invalidAccount2, validConf, true},
                    {null, validConf, true}
            });
        }

        @Test
        public void testEnforce(){
            DefaultAccountRule defaultAccountRule = new DefaultAccountRule();
            defaultAccountRule.setConf(conf);
            try{
                defaultAccountRule.enforce(account);
                //assertFalse(expectedException);
                if(expectedException)
                    fail("Expected AccountPolicyException but no exception was thrown");
            } catch (Exception e) {
                assertTrue(expectedException);
            }
        }
    }
}
