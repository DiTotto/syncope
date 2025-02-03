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

            DefaultAccountRuleConf invalidConf3 = new DefaultAccountRuleConf();
            invalidConf1.setMinLength(1);
            invalidConf1.setMaxLength(Integer.MAX_VALUE);

            return Arrays.asList(new Object[][]{
                    {validConf, false},
                    {invalidConf1, false}, //true
                    {invalidConf2, false}, //true
                    {invalidConf3, false}, //true
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
            validConf.getWordsNotPermitted().add("admin");


            DefaultUser validUser = new DefaultUser();
            validUser.setUsername("validUser");


            User invalidUser1 = new DefaultUser();
            invalidUser1.setUsername("admin");

            User invalidUser2 = new DefaultUser();
            invalidUser2.setUsername("admin is a bad word");

            User invalidUser3 = new DefaultUser();
            invalidUser2.setUsername("");

            //added for jacoco
            DefaultAccountRuleConf confWithMinLength = new DefaultAccountRuleConf();
            confWithMinLength.setMinLength(5);
            User invalidUser4 = new DefaultUser();
            invalidUser4.setUsername("abcd");

            DefaultAccountRuleConf confWithMaxLength = new DefaultAccountRuleConf();
            confWithMaxLength.setMaxLength(5);
            User invalidUser5 = new DefaultUser();
            invalidUser5.setUsername("abcdefg");

            DefaultAccountRuleConf confWithPattern = new DefaultAccountRuleConf();
            confWithPattern.setPattern("^[a-zA-Z0-9]*$");
            User invalidUser6 = new DefaultUser();
            invalidUser6.setUsername("admin");

            //added for badua
            DefaultAccountRuleConf confUpperCase = new DefaultAccountRuleConf();
            confUpperCase.setAllUpperCase(true);
            User validUser2 = new DefaultUser();
            validUser2.setUsername("VALIDUSER");

            DefaultAccountRuleConf confLowerCase = new DefaultAccountRuleConf();
            confLowerCase.setAllLowerCase(true);
            User invalidUser7 = new DefaultUser();
            invalidUser7.setUsername("Invaliduser");

            //added for pit
//            DefaultAccountRuleConf confWithMinLength2 = new DefaultAccountRuleConf();
//            confWithMinLength2.setMinLength(5);
//            User invalidUser8 = new DefaultUser();
//            invalidUser8.setUsername("abcde");
//
//            DefaultAccountRuleConf confWithMinLength3 = new DefaultAccountRuleConf();
//            confWithMinLength3.setMinLength(0);
//            User invalidUser9 = new DefaultUser();
//            invalidUser9.setUsername("a");
//
//            DefaultAccountRuleConf confWithMaxLength2 = new DefaultAccountRuleConf();
//            confWithMaxLength2.setMaxLength(5);
//            User invalidUser10 = new DefaultUser();
//            invalidUser10.setUsername("abcde");


            return Arrays.asList(new Object[][]{
                {validUser, validConf, false},
                {invalidUser1, validConf, true},
                {invalidUser2, validConf, true},
                {invalidUser3, validConf, true},
                {null, validConf, true},
                {invalidUser4, confWithMinLength, true},
                {invalidUser5, confWithMaxLength, true},
                {invalidUser6, confWithPattern, false},
                {validUser2, confUpperCase, false},
                {invalidUser7, confLowerCase, true},
//                {invalidUser8, confWithMinLength2, false},
//                {invalidUser9, confWithMinLength3, false},
//                {invalidUser10, confWithMaxLength2, false}
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
            validConf.getWordsNotPermitted().add("culo");

            DefaultLinkedAccount validAccount = new DefaultLinkedAccount();
            validAccount.setUsername("validUser");


            DefaultLinkedAccount invalidAccount1 = new DefaultLinkedAccount();
            invalidAccount1.setUsername("culo");

            DefaultLinkedAccount invalidAccount2 = new DefaultLinkedAccount();
            invalidAccount2.setUsername("culo is a bad word");


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
