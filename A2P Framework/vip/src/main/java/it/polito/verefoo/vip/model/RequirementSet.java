package it.polito.verefoo.vip.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;

import java.util.Set;

@JacksonXmlRootElement(localName = "PropertyDefinition")
public class RequirementSet {
    @JacksonXmlElementWrapper(useWrapping = false)
    @JacksonXmlProperty(localName = "Property")
    private final Set<Requirement> requirement;

    public RequirementSet(Set<Requirement> requirement) {
        this.requirement = requirement;
    }
}
