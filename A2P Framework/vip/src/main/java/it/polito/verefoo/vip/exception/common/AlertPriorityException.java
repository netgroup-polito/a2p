package it.polito.verefoo.vip.exception.common;

import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class AlertPriorityException extends PriorityException {
    public AlertPriorityException(AbstractParserStrategy.ParsingContext context, int lowestPriorityLevel, int highestPriorityLevel) {
        super("Invalid priority level inside alert: " + context.getAlertPriority() + ". Priority must be between "
                + lowestPriorityLevel + " (LOWEST) and " + highestPriorityLevel + " (HIGHEST). " +
                "Caused by: '" + context.getAlertString() + "'");
    }
}
