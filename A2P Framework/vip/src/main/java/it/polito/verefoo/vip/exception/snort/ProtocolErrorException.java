package it.polito.verefoo.vip.exception.snort;

import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class ProtocolErrorException extends RuntimeException {
    public ProtocolErrorException(AbstractParserStrategy.ParsingContext context) {
        super("'Error' protocol type detected: '" + context.getAlertString() + "'");
    }
}
