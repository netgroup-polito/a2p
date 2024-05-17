package it.polito.verefoo.vip.exception.common;

import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class MalformedAlertException extends RuntimeException {
    public MalformedAlertException(AbstractParserStrategy.ParsingContext context) {
        super("Malformed alert detected (this may result from missing required fields, inappropriate spacing, or other formatting errors): '" + context.getAlertString() + "'");
    }
}
