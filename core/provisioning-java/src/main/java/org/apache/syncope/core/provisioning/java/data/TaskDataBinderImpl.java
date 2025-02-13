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
package org.apache.syncope.core.provisioning.java.data;

import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.syncope.common.lib.SyncopeClientException;
import org.apache.syncope.common.lib.command.CommandArgs;
import org.apache.syncope.common.lib.command.CommandTO;
import org.apache.syncope.common.lib.to.ExecTO;
import org.apache.syncope.common.lib.to.MacroTaskTO;
import org.apache.syncope.common.lib.to.NotificationTaskTO;
import org.apache.syncope.common.lib.to.PropagationTaskTO;
import org.apache.syncope.common.lib.to.ProvisioningTaskTO;
import org.apache.syncope.common.lib.to.PullTaskTO;
import org.apache.syncope.common.lib.to.PushTaskTO;
import org.apache.syncope.common.lib.to.SchedTaskTO;
import org.apache.syncope.common.lib.to.TaskTO;
import org.apache.syncope.common.lib.types.ClientExceptionType;
import org.apache.syncope.common.lib.types.IdRepoImplementationType;
import org.apache.syncope.common.lib.types.ImplementationEngine;
import org.apache.syncope.common.lib.types.JobType;
import org.apache.syncope.common.lib.types.MatchingRule;
import org.apache.syncope.common.lib.types.TaskType;
import org.apache.syncope.common.lib.types.UnmatchingRule;
import org.apache.syncope.core.persistence.api.dao.AnyTypeDAO;
import org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO;
import org.apache.syncope.core.persistence.api.dao.ImplementationDAO;
import org.apache.syncope.core.persistence.api.dao.NotFoundException;
import org.apache.syncope.core.persistence.api.dao.RealmDAO;
import org.apache.syncope.core.persistence.api.dao.TaskExecDAO;
import org.apache.syncope.core.persistence.api.entity.AnyType;
import org.apache.syncope.core.persistence.api.entity.EntityFactory;
import org.apache.syncope.core.persistence.api.entity.Implementation;
import org.apache.syncope.core.persistence.api.entity.task.AnyTemplatePullTask;
import org.apache.syncope.core.persistence.api.entity.task.MacroTask;
import org.apache.syncope.core.persistence.api.entity.task.NotificationTask;
import org.apache.syncope.core.persistence.api.entity.task.PropagationTask;
import org.apache.syncope.core.persistence.api.entity.task.ProvisioningTask;
import org.apache.syncope.core.persistence.api.entity.task.PullTask;
import org.apache.syncope.core.persistence.api.entity.task.PushTask;
import org.apache.syncope.core.persistence.api.entity.task.SchedTask;
import org.apache.syncope.core.persistence.api.entity.task.Task;
import org.apache.syncope.core.persistence.api.entity.task.TaskExec;
import org.apache.syncope.core.persistence.api.entity.task.TaskUtils;
import org.apache.syncope.core.persistence.api.entity.task.TaskUtilsFactory;
import org.apache.syncope.core.provisioning.api.data.TaskDataBinder;
import org.apache.syncope.core.provisioning.api.job.JobNamer;
import org.apache.syncope.core.provisioning.java.pushpull.PullJobDelegate;
import org.apache.syncope.core.provisioning.java.pushpull.PushJobDelegate;
import org.apache.syncope.core.provisioning.java.utils.TemplateUtils;
import org.apache.syncope.core.spring.implementation.ImplementationManager;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.Trigger;
import org.quartz.TriggerKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.quartz.SchedulerFactoryBean;

public class TaskDataBinderImpl extends AbstractExecutableDatabinder implements TaskDataBinder {

    protected static final Logger LOG = LoggerFactory.getLogger(TaskDataBinder.class);

    protected static final String MACRO_RUN_JOB_DELEGATE = "org.apache.syncope.core.logic.job.MacroRunJobDelegate";

    protected final RealmDAO realmDAO;

    protected final ExternalResourceDAO resourceDAO;

    protected final TaskExecDAO taskExecDAO;

    protected final AnyTypeDAO anyTypeDAO;

    protected final ImplementationDAO implementationDAO;

    protected final EntityFactory entityFactory;

    protected final SchedulerFactoryBean scheduler;

    protected final TaskUtilsFactory taskUtilsFactory;

    public TaskDataBinderImpl(
            final RealmDAO realmDAO,
            final ExternalResourceDAO resourceDAO,
            final TaskExecDAO taskExecDAO,
            final AnyTypeDAO anyTypeDAO,
            final ImplementationDAO implementationDAO,
            final EntityFactory entityFactory,
            final SchedulerFactoryBean scheduler,
            final TaskUtilsFactory taskUtilsFactory) {

        this.realmDAO = realmDAO;
        this.resourceDAO = resourceDAO;
        this.taskExecDAO = taskExecDAO;
        this.anyTypeDAO = anyTypeDAO;
        this.implementationDAO = implementationDAO;
        this.entityFactory = entityFactory;
        this.scheduler = scheduler;
        this.taskUtilsFactory = taskUtilsFactory;
    }

    protected void fill(final ProvisioningTask<?> provisioningTask, final ProvisioningTaskTO provisioningTaskTO) {
        if (provisioningTask instanceof PushTask && provisioningTaskTO instanceof PushTaskTO) {
            PushTask pushTask = (PushTask) provisioningTask;
            PushTaskTO pushTaskTO = (PushTaskTO) provisioningTaskTO;

            Implementation jobDelegate = pushTaskTO.getJobDelegate() == null
                    ? implementationDAO.findByType(IdRepoImplementationType.TASKJOB_DELEGATE).stream().
                            filter(impl -> PushJobDelegate.class.getName().equals(impl.getBody())).
                            findFirst().orElse(null)
                    : implementationDAO.find(pushTaskTO.getJobDelegate());
            if (jobDelegate == null) {
                jobDelegate = entityFactory.newEntity(Implementation.class);
                jobDelegate.setKey(PushJobDelegate.class.getSimpleName());
                jobDelegate.setEngine(ImplementationEngine.JAVA);
                jobDelegate.setType(IdRepoImplementationType.TASKJOB_DELEGATE);
                jobDelegate.setBody(PushJobDelegate.class.getName());
                jobDelegate = implementationDAO.save(jobDelegate);
            }
            pushTask.setJobDelegate(jobDelegate);

            pushTask.setSourceRealm(realmDAO.findByFullPath(pushTaskTO.getSourceRealm()));

            pushTask.setMatchingRule(pushTaskTO.getMatchingRule() == null
                    ? MatchingRule.LINK : pushTaskTO.getMatchingRule());
            pushTask.setUnmatchingRule(pushTaskTO.getUnmatchingRule() == null
                    ? UnmatchingRule.ASSIGN : pushTaskTO.getUnmatchingRule());

            pushTaskTO.getFilters().forEach((type, fiql) -> {
                AnyType anyType = anyTypeDAO.find(type);
                if (anyType == null) {
                    LOG.debug("Invalid AnyType {} specified, ignoring...", type);
                } else {
                    pushTask.getFilters().put(anyType.getKey(), fiql);
                }
            });
            // remove all filters not contained in the TO
            pushTask.getFilters().entrySet().
                    removeIf(filter -> !pushTaskTO.getFilters().containsKey(filter.getKey()));

            pushTask.setConcurrentSettings(pushTaskTO.getConcurrentSettings());
        } else if (provisioningTask instanceof PullTask && provisioningTaskTO instanceof PullTaskTO) {
            PullTask pullTask = (PullTask) provisioningTask;
            PullTaskTO pullTaskTO = (PullTaskTO) provisioningTaskTO;

            Implementation jobDelegate = pullTaskTO.getJobDelegate() == null
                    ? implementationDAO.findByType(IdRepoImplementationType.TASKJOB_DELEGATE).stream().
                            filter(impl -> PullJobDelegate.class.getName().equals(impl.getBody())).
                            findFirst().orElse(null)
                    : implementationDAO.find(pullTaskTO.getJobDelegate());
            if (jobDelegate == null) {
                jobDelegate = entityFactory.newEntity(Implementation.class);
                jobDelegate.setKey(PullJobDelegate.class.getSimpleName());
                jobDelegate.setEngine(ImplementationEngine.JAVA);
                jobDelegate.setType(IdRepoImplementationType.TASKJOB_DELEGATE);
                jobDelegate.setBody(PullJobDelegate.class.getName());
                jobDelegate = implementationDAO.save(jobDelegate);
            }
            pullTask.setJobDelegate(jobDelegate);

            pullTask.setPullMode(pullTaskTO.getPullMode());

            if (pullTaskTO.getReconFilterBuilder() == null) {
                pullTask.setReconFilterBuilder(null);
            } else {
                Optional.ofNullable(implementationDAO.find(pullTaskTO.getReconFilterBuilder())).ifPresentOrElse(
                        pullTask::setReconFilterBuilder,
                        () -> LOG.debug("Invalid Implementation {}, ignoring...", pullTaskTO.getReconFilterBuilder()));
            }

            pullTask.setDestinationRealm(realmDAO.findByFullPath(pullTaskTO.getDestinationRealm()));

            pullTask.setMatchingRule(pullTaskTO.getMatchingRule() == null
                    ? MatchingRule.UPDATE : pullTaskTO.getMatchingRule());
            pullTask.setUnmatchingRule(pullTaskTO.getUnmatchingRule() == null
                    ? UnmatchingRule.PROVISION : pullTaskTO.getUnmatchingRule());

            // validate JEXL expressions from templates and proceed if fine
            TemplateUtils.check(pullTaskTO.getTemplates(), ClientExceptionType.InvalidPullTask);
            pullTaskTO.getTemplates().forEach((type, template) -> {
                AnyType anyType = anyTypeDAO.find(type);
                if (anyType == null) {
                    LOG.debug("Invalid AnyType {} specified, ignoring...", type);
                } else {
                    AnyTemplatePullTask anyTemplate = pullTask.getTemplate(anyType.getKey()).orElse(null);
                    if (anyTemplate == null) {
                        anyTemplate = entityFactory.newEntity(AnyTemplatePullTask.class);
                        anyTemplate.setAnyType(anyType);
                        anyTemplate.setPullTask(pullTask);

                        pullTask.add(anyTemplate);
                    }
                    anyTemplate.set(template);
                }
            });
            // remove all templates not contained in the TO
            pullTask.getTemplates().
                    removeIf(anyTemplate -> !pullTaskTO.getTemplates().containsKey(anyTemplate.getAnyType().getKey()));

            pullTask.setRemediation(pullTaskTO.isRemediation());

            pullTask.setConcurrentSettings(pullTaskTO.getConcurrentSettings());
        }

        // 3. fill the remaining fields
        provisioningTask.setPerformCreate(provisioningTaskTO.isPerformCreate());
        provisioningTask.setPerformUpdate(provisioningTaskTO.isPerformUpdate());
        provisioningTask.setPerformDelete(provisioningTaskTO.isPerformDelete());
        provisioningTask.setSyncStatus(provisioningTaskTO.isSyncStatus());

        provisioningTaskTO.getActions().forEach(
                action -> Optional.ofNullable(implementationDAO.find(action)).ifPresentOrElse(
                        provisioningTask::add,
                        () -> LOG.debug("Invalid Implementation {}, ignoring...", action)));
        // remove all implementations not contained in the TO
        provisioningTask.getActions().removeIf(impl -> !provisioningTaskTO.getActions().contains(impl.getKey()));
    }

    protected void fill(final MacroTask macroTask, final MacroTaskTO macroTaskTO) {
        macroTask.setRealm(Optional.ofNullable(realmDAO.findByFullPath(macroTaskTO.getRealm())).
                orElseThrow(() -> new NotFoundException("Realm " + macroTaskTO.getRealm())));

        macroTaskTO.getCommands().
                forEach(command -> Optional.ofNullable(implementationDAO.find(command.getKey())).ifPresentOrElse(
                impl -> {
                    try {
                        CommandArgs args = command.getArgs();
                        if (args == null) {
                            args = ImplementationManager.emptyArgs(impl);
                        }

                        macroTask.add(impl, args);
                    } catch (Exception e) {
                        LOG.error("While adding Command {} to Macro", impl.getKey(), e);

                        SyncopeClientException sce = SyncopeClientException.build(
                                ClientExceptionType.InvalidImplementationType);
                        sce.getElements().add("While adding Command " + impl.getKey() + ": " + e.getMessage());
                        throw sce;
                    }
                },
                () -> LOG.error("Could not find Command {}", command.getKey())));

        macroTask.setContinueOnError(macroTaskTO.isContinueOnError());
        macroTask.setSaveExecs(macroTaskTO.isSaveExecs());
    }

    @Override
    public SchedTask createSchedTask(final SchedTaskTO taskTO, final TaskUtils taskUtils) {
        Class<? extends TaskTO> taskTOClass = taskUtils.taskTOClass();
        if (taskTOClass == null || !taskTOClass.equals(taskTO.getClass())) {
            throw new IllegalArgumentException(String.format("Expected %s, found %s", taskTOClass, taskTO.getClass()));
        }

        SchedTask task = taskUtils.newTask();
        task.setStartAt(taskTO.getStartAt());
        task.setCronExpression(taskTO.getCronExpression());
        task.setName(taskTO.getName());
        task.setDescription(taskTO.getDescription());
        task.setActive(taskTO.isActive());

        if (taskUtils.getType() == TaskType.SCHEDULED) {
            task.setJobDelegate(Optional.ofNullable(implementationDAO.find(taskTO.getJobDelegate())).
                    orElseThrow(() -> new NotFoundException("JobDelegate " + taskTO.getJobDelegate())));
        } else if (taskTO instanceof MacroTaskTO) {
            MacroTaskTO macroTaskTO = (MacroTaskTO) taskTO;
            MacroTask macroTask = (MacroTask) task;

            Implementation jobDelegate = macroTaskTO.getJobDelegate() == null
                    ? implementationDAO.findByType(IdRepoImplementationType.TASKJOB_DELEGATE).stream().
                            filter(impl -> MACRO_RUN_JOB_DELEGATE.equals(impl.getBody())).
                            findFirst().orElse(null)
                    : implementationDAO.find(macroTaskTO.getJobDelegate());
            if (jobDelegate == null) {
                jobDelegate = entityFactory.newEntity(Implementation.class);
                jobDelegate.setKey(StringUtils.substringAfterLast(MACRO_RUN_JOB_DELEGATE, "."));
                jobDelegate.setEngine(ImplementationEngine.JAVA);
                jobDelegate.setType(IdRepoImplementationType.TASKJOB_DELEGATE);
                jobDelegate.setBody(MACRO_RUN_JOB_DELEGATE);
                jobDelegate = implementationDAO.save(jobDelegate);
            }
            macroTask.setJobDelegate(jobDelegate);

            macroTask.setRealm(Optional.ofNullable(realmDAO.findByFullPath(macroTaskTO.getRealm())).
                    orElseThrow(() -> new NotFoundException("Realm " + macroTaskTO.getRealm())));

            fill(macroTask, macroTaskTO);
        } else if (taskTO instanceof ProvisioningTaskTO) {
            ProvisioningTaskTO provisioningTaskTO = (ProvisioningTaskTO) taskTO;
            ProvisioningTask<?> provisioningTask = (ProvisioningTask<?>) task;

            provisioningTask.setResource(Optional.ofNullable(resourceDAO.find(provisioningTaskTO.getResource())).
                    orElseThrow(() -> new NotFoundException("Resource " + provisioningTaskTO.getResource())));

            fill(provisioningTask, provisioningTaskTO);
        }

        return task;
    }

    @Override
    public void updateSchedTask(final SchedTask task, final SchedTaskTO taskTO, final TaskUtils taskUtils) {
        Class<? extends TaskTO> taskTOClass = taskUtils.taskTOClass();
        if (taskTOClass == null || !taskTOClass.equals(taskTO.getClass())) {
            throw new IllegalArgumentException(String.format("Expected %s, found %s", taskTOClass, taskTO.getClass()));
        }

        if (StringUtils.isBlank(taskTO.getName())) {
            SyncopeClientException sce = SyncopeClientException.build(ClientExceptionType.RequiredValuesMissing);
            sce.getElements().add("name");
            throw sce;
        }

        task.setName(taskTO.getName());
        task.setDescription(taskTO.getDescription());
        task.setCronExpression(taskTO.getCronExpression());
        task.setActive(taskTO.isActive());

        if (task instanceof MacroTask) {
            MacroTaskTO macroTaskTO = (MacroTaskTO) taskTO;
            MacroTask macroTask = (MacroTask) task;

            macroTask.getCommands().clear();
            macroTask.getCommandArgs().clear();

            fill(macroTask, macroTaskTO);
        } else if (task instanceof ProvisioningTask) {
            fill((ProvisioningTask) task, (ProvisioningTaskTO) taskTO);
        }
    }

    @Override
    public String buildRefDesc(final Task<?> task) {
        return taskUtilsFactory.getInstance(task).getType().name() + ' '
                + "Task "
                + task.getKey() + ' '
                + (task instanceof SchedTask
                        ? SchedTask.class.cast(task).getName()
                        : task instanceof PropagationTask
                                ? PropagationTask.class.cast(task).getConnObjectKey()
                                : StringUtils.EMPTY);
    }

    @Override
    public ExecTO getExecTO(final TaskExec<?> execution) {
        ExecTO execTO = new ExecTO();
        execTO.setKey(execution.getKey());
        execTO.setStatus(execution.getStatus());
        execTO.setMessage(execution.getMessage());
        execTO.setStart(execution.getStart());
        execTO.setEnd(execution.getEnd());
        execTO.setExecutor(execution.getExecutor());

        if (execution.getTask() != null && execution.getTask().getKey() != null) {
            execTO.setJobType(JobType.TASK);
            execTO.setRefKey(execution.getTask().getKey());
            execTO.setRefDesc(buildRefDesc(execution.getTask()));
        }

        return execTO;
    }

    protected void fill(final SchedTaskTO schedTaskTO, final SchedTask schedTask) {
        schedTaskTO.setName(schedTask.getName());
        schedTaskTO.setDescription(schedTask.getDescription());
        schedTaskTO.setCronExpression(schedTask.getCronExpression());
        schedTaskTO.setActive(schedTask.isActive());

        schedTaskTO.setLastExec(schedTaskTO.getStart());

        String triggerName = JobNamer.getTriggerName(JobNamer.getJobKey(schedTask).getName());
        try {
            Trigger trigger = scheduler.getScheduler().getTrigger(new TriggerKey(triggerName, Scheduler.DEFAULT_GROUP));
            if (trigger != null) {
                schedTaskTO.setLastExec(toOffsetDateTime(trigger.getPreviousFireTime()));
                schedTaskTO.setNextExec(toOffsetDateTime(trigger.getNextFireTime()));
            }
        } catch (SchedulerException e) {
            LOG.warn("While trying to get to " + triggerName, e);
        }

        if (schedTaskTO instanceof ProvisioningTaskTO && schedTask instanceof ProvisioningTask) {
            ProvisioningTaskTO provisioningTaskTO = (ProvisioningTaskTO) schedTaskTO;
            ProvisioningTask<?> provisioningTask = (ProvisioningTask<?>) schedTask;

            provisioningTaskTO.setResource(provisioningTask.getResource().getKey());

            provisioningTaskTO.getActions().addAll(
                    provisioningTask.getActions().stream().map(Implementation::getKey).collect(Collectors.toList()));

            provisioningTaskTO.setPerformCreate(provisioningTask.isPerformCreate());
            provisioningTaskTO.setPerformUpdate(provisioningTask.isPerformUpdate());
            provisioningTaskTO.setPerformDelete(provisioningTask.isPerformDelete());
            provisioningTaskTO.setSyncStatus(provisioningTask.isSyncStatus());
        }
    }

    @Override
    public <T extends TaskTO> T getTaskTO(final Task<?> task, final TaskUtils taskUtils, final boolean details) {
        T taskTO = taskUtils.newTaskTO();
        taskTO.setKey(task.getKey());

        Optional.ofNullable(taskExecDAO.findLatestStarted(taskUtils.getType(), task)).ifPresentOrElse(
                latestExec -> {
                    taskTO.setLatestExecStatus(latestExec.getStatus());
                    taskTO.setStart(latestExec.getStart());
                    taskTO.setEnd(latestExec.getEnd());
                    taskTO.setLastExecutor(latestExec.getExecutor());
                },
                () -> taskTO.setLatestExecStatus(StringUtils.EMPTY));

        if (details) {
            task.getExecs().stream().
                    filter(Objects::nonNull).
                    forEach(execution -> taskTO.getExecutions().add(getExecTO(execution)));
        }

        switch (taskUtils.getType()) {
            case PROPAGATION:
                PropagationTask propagationTask = (PropagationTask) task;
                PropagationTaskTO propagationTaskTO = (PropagationTaskTO) taskTO;

                propagationTaskTO.setOperation(propagationTask.getOperation());
                propagationTaskTO.setConnObjectKey(propagationTask.getConnObjectKey());
                propagationTaskTO.setOldConnObjectKey(propagationTask.getOldConnObjectKey());
                propagationTaskTO.setPropagationData(propagationTask.getSerializedPropagationData());
                propagationTaskTO.setResource(propagationTask.getResource().getKey());
                propagationTaskTO.setObjectClassName(propagationTask.getObjectClassName());
                propagationTaskTO.setAnyTypeKind(propagationTask.getAnyTypeKind());
                propagationTaskTO.setAnyType(propagationTask.getAnyType());
                propagationTaskTO.setEntityKey(propagationTask.getEntityKey());
                break;

            case SCHEDULED:
                SchedTask schedTask = (SchedTask) task;
                SchedTaskTO schedTaskTO = (SchedTaskTO) taskTO;

                schedTaskTO.setJobDelegate(schedTask.getJobDelegate().getKey());

                fill(schedTaskTO, schedTask);
                break;

            case MACRO:
                MacroTask macroTask = (MacroTask) task;
                MacroTaskTO macroTaskTO = (MacroTaskTO) taskTO;

                macroTaskTO.setJobDelegate(macroTask.getJobDelegate().getKey());
                macroTaskTO.setRealm(macroTask.getRealm().getFullPath());
                for (int i = 0; i < macroTask.getCommands().size(); i++) {
                    macroTaskTO.getCommands().add(
                            new CommandTO.Builder(macroTask.getCommands().get(i).getKey()).
                                    args(macroTask.getCommandArgs().get(i)).build());
                }
                macroTaskTO.setContinueOnError(macroTask.isContinueOnError());
                macroTaskTO.setSaveExecs(macroTask.isSaveExecs());

                fill(macroTaskTO, macroTask);
                break;

            case PULL:
                PullTask pullTask = (PullTask) task;
                PullTaskTO pullTaskTO = (PullTaskTO) taskTO;

                fill(pullTaskTO, pullTask);

                pullTaskTO.setDestinationRealm(pullTask.getDestinationRealm().getFullPath());
                pullTaskTO.setMatchingRule(pullTask.getMatchingRule() == null
                        ? MatchingRule.UPDATE : pullTask.getMatchingRule());
                pullTaskTO.setUnmatchingRule(pullTask.getUnmatchingRule() == null
                        ? UnmatchingRule.PROVISION : pullTask.getUnmatchingRule());
                pullTaskTO.setPullMode(pullTask.getPullMode());

                if (pullTask.getReconFilterBuilder() != null) {
                    pullTaskTO.setReconFilterBuilder(pullTask.getReconFilterBuilder().getKey());
                }

                pullTask.getTemplates().
                        forEach(template -> pullTaskTO.getTemplates().
                        put(template.getAnyType().getKey(), template.get()));

                pullTaskTO.setRemediation(pullTask.isRemediation());

                pullTaskTO.setConcurrentSettings(pullTask.getConcurrentSettings());
                break;

            case PUSH:
                PushTask pushTask = (PushTask) task;
                PushTaskTO pushTaskTO = (PushTaskTO) taskTO;

                fill(pushTaskTO, pushTask);

                pushTaskTO.setSourceRealm(pushTask.getSourceRealm().getFullPath());
                pushTaskTO.setMatchingRule(pushTask.getMatchingRule() == null
                        ? MatchingRule.LINK : pushTask.getMatchingRule());
                pushTaskTO.setUnmatchingRule(pushTask.getUnmatchingRule() == null
                        ? UnmatchingRule.ASSIGN : pushTask.getUnmatchingRule());

                pushTaskTO.getFilters().putAll(pushTask.getFilters());

                pushTaskTO.setConcurrentSettings(pushTask.getConcurrentSettings());
                break;

            case NOTIFICATION:
                NotificationTask notificationTask = (NotificationTask) task;
                NotificationTaskTO notificationTaskTO = (NotificationTaskTO) taskTO;

                notificationTaskTO.setNotification(notificationTask.getNotification().getKey());
                notificationTaskTO.setAnyTypeKind(notificationTask.getAnyTypeKind());
                notificationTaskTO.setEntityKey(notificationTask.getEntityKey());
                notificationTaskTO.setSender(notificationTask.getSender());
                notificationTaskTO.getRecipients().addAll(notificationTask.getRecipients());
                notificationTaskTO.setSubject(notificationTask.getSubject());
                notificationTaskTO.setHtmlBody(notificationTask.getHtmlBody());
                notificationTaskTO.setTextBody(notificationTask.getTextBody());
                notificationTaskTO.setExecuted(notificationTask.isExecuted());
                if (notificationTask.isExecuted() && StringUtils.isBlank(taskTO.getLatestExecStatus())) {
                    taskTO.setLatestExecStatus("[EXECUTED]");
                }
                notificationTaskTO.setTraceLevel(notificationTask.getTraceLevel());
                break;

            default:
        }

        return taskTO;
    }
}
