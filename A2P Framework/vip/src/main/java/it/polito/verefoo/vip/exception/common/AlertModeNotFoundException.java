package it.polito.verefoo.vip.exception.common;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class AlertModeNotFoundException extends RuntimeException {
    public AlertModeNotFoundException(String alertMode) {
        super("The following alert mode is not supported: " + alertMode);
    }
}
