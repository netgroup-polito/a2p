package it.polito.verefoo.vip.exception.common;

import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidIPsException extends RuntimeException {
    public InvalidIPsException(AbstractParserStrategy.ParsingContext context) {
        super("Invalid IP(s) detected: '" + context.getAlertString() + "'");
    }
}
