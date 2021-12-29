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
import io.swagger.annotations.ApiModel;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

/**
 * The type of the token issued i.e Bearer
 */
@JsonAdapter(TokenTypeModel.Adapter.class)
public enum TokenTypeModel {
  
  BEARER("Bearer");

  private String value;

  TokenTypeModel(String value) {
    this.value = value;
  }

  public String getValue() {
    return value;
  }

  @Override
  public String toString() {
    return String.valueOf(value);
  }

  public static TokenTypeModel fromValue(String value) {
    for (TokenTypeModel b : TokenTypeModel.values()) {
      if (b.value.equals(value)) {
        return b;
      }
    }
    throw new IllegalArgumentException("Unexpected value '" + value + "'");
  }

  public static class Adapter extends TypeAdapter<TokenTypeModel> {
    @Override
    public void write(final JsonWriter jsonWriter, final TokenTypeModel enumeration) throws IOException {
      jsonWriter.value(enumeration.getValue());
    }

    @Override
    public TokenTypeModel read(final JsonReader jsonReader) throws IOException {
      String value = jsonReader.nextString();
      return TokenTypeModel.fromValue(value);
    }
  }
}

