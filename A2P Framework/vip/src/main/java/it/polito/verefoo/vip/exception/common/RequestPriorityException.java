package it.polito.verefoo.vip.exception.common;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class RequestPriorityException extends PriorityException {
    public RequestPriorityException(int wrongPriorityLevel, int lowestPriorityLevel, int highestPriorityLevel) {
        super("Invalid priority level inside request parameter: " + wrongPriorityLevel + ". Priority must be between "
                + lowestPriorityLevel + " (LOWEST) and " + highestPriorityLevel + " (HIGHEST).");
    }
}
