package it.polito.verefoo.vip.exception.common;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class StrategyNotSetException extends RuntimeException {
    public StrategyNotSetException() {
        super("No strategy set for the selected parser");
    }
}
