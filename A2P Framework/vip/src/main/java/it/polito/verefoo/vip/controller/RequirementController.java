package it.polito.verefoo.vip.controller;

import it.polito.verefoo.vip.exception.common.RequestStreamException;
import it.polito.verefoo.vip.model.RequirementSet;
import it.polito.verefoo.vip.parser.AbstractParser;
import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import it.polito.verefoo.vip.parser.ParserRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.Min;
import java.io.IOException;
import java.io.InputStream;

@RestController
@Validated
public class RequirementController {
    private final ParserRegistry parserRegistry;

    @Autowired
    public RequirementController(ParserRegistry parserRegistry) {
        this.parserRegistry = parserRegistry;
    }

    @PostMapping(value = "/api/parser/{idsName}/{idsVersion}/{alertMode}", produces = MediaType.APPLICATION_XML_VALUE)
    public RequirementSet parseAlerts(
            HttpServletRequest request,
            @PathVariable String idsName,
            @PathVariable String idsVersion,
            @PathVariable String alertMode,
            @RequestParam(value = "priority", required = false) Integer priority,
            @RequestParam(value = "graph", required = false) @Min(0) Integer graph) {
        AbstractParser parser = parserRegistry.getParser(idsName, idsVersion);
        AbstractParserStrategy strategy = parserRegistry.getStrategy(parser, alertMode);

        try (InputStream inputStream = request.getInputStream()) {
            return new RequirementSet(parser.parse(inputStream, priority, graph, strategy));
        } catch (IOException e) {
            throw new RequestStreamException();
        }
    }
}
