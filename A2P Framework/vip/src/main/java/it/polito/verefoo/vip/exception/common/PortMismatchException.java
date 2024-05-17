package it.polito.verefoo.vip.exception.common;

import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class PortMismatchException extends RuntimeException {
    public PortMismatchException(AbstractParserStrategy.ParsingContext context) {
        super("Both ports should be either defined or omitted: '" + context.getAlertString() + "'");
    }
}
