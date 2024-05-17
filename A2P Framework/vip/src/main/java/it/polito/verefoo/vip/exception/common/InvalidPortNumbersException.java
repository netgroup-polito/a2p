package it.polito.verefoo.vip.exception.common;

import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidPortNumbersException extends RuntimeException {
    public InvalidPortNumbersException(AbstractParserStrategy.ParsingContext context) {
        super("Invalid port number(s) detected: '" + context.getAlertString() + "'");
    }
}
