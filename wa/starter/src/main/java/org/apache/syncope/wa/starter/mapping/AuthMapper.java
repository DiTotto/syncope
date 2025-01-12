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
package org.apache.syncope.wa.starter.mapping;

import java.util.List;
import org.apache.syncope.common.lib.policy.AuthPolicyConf;
import org.apache.syncope.common.lib.policy.AuthPolicyTO;
import org.apache.syncope.common.lib.to.AuthModuleTO;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ConfigurableApplicationContext;

public interface AuthMapper {

    boolean supports(AuthPolicyConf conf);

    AuthMapperResult build(
            ConfigurableApplicationContext ctx,
            String pac4jCoreName,
            ObjectProvider<AuthenticationEventExecutionPlan> authenticationEventExecutionPlan,
            AuthPolicyTO policy,
            List<AuthModuleTO> authModules);
}
