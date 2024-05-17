package it.polito.verefoo.vip.exception.common;

import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class SamePortTypeException extends RuntimeException {
    public SamePortTypeException(AbstractParserStrategy.ParsingContext context) {
        super("Both source and destination ports must NOT be of the same type (ephemeral or non-ephemeral): " +
                "'" + context.getAlertString() + "'");
    }
}
