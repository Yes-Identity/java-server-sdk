/*
 * Yes Identity
 * Welcome to Yes Identity API documentation.
 *
 * The version of the OpenAPI document: 1.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.yesidentity.sdk.api;

import com.yesidentity.sdk.invoker.ApiException;
import com.yesidentity.sdk.model.AttributeModel;
import com.yesidentity.sdk.model.ErrorResponseModel;
import org.junit.Test;
import org.junit.Ignore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * API tests for AttributesApi
 */
@Ignore
public class AttributesApiTest {

    private final AttributesApi api = new AttributesApi();

    
    /**
     * Create Attribute
     *
     * Create Attribute
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void createAttributeTest() throws ApiException {
        String username = null;
        AttributeModel attributeModel = null;
                AttributeModel response = api.createAttribute(username, attributeModel);
        // TODO: test validations
    }
    
    /**
     * Delete Attribute
     *
     * Delete Attribute
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void deleteAttributeTest() throws ApiException {
        String username = null;
        String name = null;
                api.deleteAttribute(username, name);
        // TODO: test validations
    }
    
    /**
     * Get Attribute
     *
     * Get Attribute
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void getAttributeTest() throws ApiException {
        String username = null;
        String name = null;
                AttributeModel response = api.getAttribute(username, name);
        // TODO: test validations
    }
    
    /**
     * Get Attributes
     *
     * Get Attributes
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @Test
    public void getAttributesTest() throws ApiException {
        String username = null;
                List<AttributeModel> response = api.getAttributes(username);
        // TODO: test validations
    }
    
}
