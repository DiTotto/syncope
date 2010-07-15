/* 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package org.syncope.console.rest;

import org.syncope.client.to.ResourceTO;
import org.syncope.client.to.ResourceTOs;
import org.syncope.client.validation.SyncopeClientCompositeErrorException;

/**
 * Console client for invoking Rest Connectors services.
 */
public class ResourcesRestClient {

    RestClient restClient;

    /**
     * Get all Connectors.
     * @return SchemaTOs
     */
    public ResourceTOs getAllResources() {
        ResourceTOs resources = null;

        try{
        resources = restClient.getRestTemplate().getForObject(restClient.getBaseURL()
                + "resource/list.json", ResourceTOs.class);
        }
        catch (SyncopeClientCompositeErrorException e) {
            e.printStackTrace();
        }

        return resources;
    }

    /**
     * Create new resource.
     * @param schemaTO
     */
    public void createResource(ResourceTO resourceTO) {
        try{
        restClient.getRestTemplate().postForObject(restClient.getBaseURL() +
                "resource/create", resourceTO, ResourceTO.class);
        }
        catch (SyncopeClientCompositeErrorException e) {
            e.printStackTrace();
        }
    }

    /**
     * Load an already existent resource by its name.
     * @param name (e.g.:surname)
     * @return schemaTO
     */
    public ResourceTO readConnector(String name) {
        ResourceTO resourceTO = null;

        try {
        resourceTO = restClient.getRestTemplate().getForObject
                (restClient.getBaseURL() + "resource/read/" + name + ".json",
                ResourceTO.class);
        }
        catch (SyncopeClientCompositeErrorException e) {
            e.printStackTrace();
        }
        return resourceTO;
    }

    /**
     * Update an already existent resource.
     * @param schemaTO updated
     */
    public void updateResource(ResourceTO connectorTO) {
        ResourceTO resourceTO = null;

        try {
        resourceTO = restClient.getRestTemplate().postForObject
                (restClient.getBaseURL() + "resource/update.json", connectorTO,
                ResourceTO.class);
        }
        catch (SyncopeClientCompositeErrorException e) {
            e.printStackTrace();
        }

    }

    /**
     * Delete an already existent resource by its name.
     * @param name (e.g.:surname)
     * @return schemaTO
     */
    public void deleteResource(String name) {
        try {
        restClient.getRestTemplate().delete(restClient.getBaseURL() +
                "resource/delete/{resourceName}.json",name);
        }
        catch (SyncopeClientCompositeErrorException e) {
            e.printStackTrace();
        }

    }

    public RestClient getRestClient() {
        return restClient;
    }

    public void setRestClient(RestClient restClient) {
        this.restClient = restClient;
    }
}