package it.polito.verefoo.vip.exception.common;

import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UnexpectedPortsException extends RuntimeException {
    public UnexpectedPortsException(AbstractParserStrategy.ParsingContext context) {
        super("Unexpected port(s) detected: '" + context.getAlertString() + "'");
    }
}
