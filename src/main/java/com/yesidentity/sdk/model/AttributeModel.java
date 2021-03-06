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


package com.yesidentity.sdk.model;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

/**
 * AttributeModel
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-01-01T07:44:54.268733600+01:00[Europe/Stockholm]")
public class AttributeModel {
  public static final String SERIALIZED_NAME_NAME = "name";
  @SerializedName(SERIALIZED_NAME_NAME)
  private String name;

  public static final String SERIALIZED_NAME_VALUE = "value";
  @SerializedName(SERIALIZED_NAME_VALUE)
  private String value;

  public static final String SERIALIZED_NAME_CREATED = "created";
  @SerializedName(SERIALIZED_NAME_CREATED)
  private Long created;

  public static final String SERIALIZED_NAME_UPDATED = "updated";
  @SerializedName(SERIALIZED_NAME_UPDATED)
  private Long updated;

  public AttributeModel() { 
  }

  
  public AttributeModel(
     Long created, 
     Long updated
  ) {
    this();
    this.created = created;
    this.updated = updated;
  }

  public AttributeModel name(String name) {
    
    this.name = name;
    return this;
  }

   /**
   * Attribute name
   * @return name
  **/
  @javax.annotation.Nonnull
  @ApiModelProperty(required = true, value = "Attribute name")

  public String getName() {
    return name;
  }


  public void setName(String name) {
    this.name = name;
  }


  public AttributeModel value(String value) {
    
    this.value = value;
    return this;
  }

   /**
   * Attribute value
   * @return value
  **/
  @javax.annotation.Nonnull
  @ApiModelProperty(required = true, value = "Attribute value")

  public String getValue() {
    return value;
  }


  public void setValue(String value) {
    this.value = value;
  }


   /**
   * Created date. Measured in seconds since the Unix epoch
   * @return created
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Created date. Measured in seconds since the Unix epoch")

  public Long getCreated() {
    return created;
  }




   /**
   * Updated date. Measured in seconds since the Unix epoch
   * @return updated
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Updated date. Measured in seconds since the Unix epoch")

  public Long getUpdated() {
    return updated;
  }




  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AttributeModel attribute = (AttributeModel) o;
    return Objects.equals(this.name, attribute.name) &&
        Objects.equals(this.value, attribute.value) &&
        Objects.equals(this.created, attribute.created) &&
        Objects.equals(this.updated, attribute.updated);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, value, created, updated);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AttributeModel {\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    value: ").append(toIndentedString(value)).append("\n");
    sb.append("    created: ").append(toIndentedString(created)).append("\n");
    sb.append("    updated: ").append(toIndentedString(updated)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}

