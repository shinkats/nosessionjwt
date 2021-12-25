package com.example.nosessionjwt.jpa.converter

import com.fasterxml.jackson.databind.ObjectMapper
import javax.persistence.AttributeConverter
import javax.persistence.Converter

@Converter
class JpaConverterJson : AttributeConverter<Any?, String?> {
    private val objectMapper = ObjectMapper()

    override fun convertToDatabaseColumn(meta: Any?): String? = objectMapper.writeValueAsString(meta)

    override fun convertToEntityAttribute(dbData: String?): Any? = objectMapper.readValue(dbData, Any::class.java)
}
