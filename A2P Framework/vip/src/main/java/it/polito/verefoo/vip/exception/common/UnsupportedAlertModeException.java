package it.polito.verefoo.vip.exception.common;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Set;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UnsupportedAlertModeException extends RuntimeException {
    public UnsupportedAlertModeException(String idsName, String idsVersion, String alertMode, Set<String> availableAlertModes) {
        super("Alert mode " + alertMode + " is not supported for " + idsName + ", version " + idsVersion +
                ". Available alert modes: " + availableAlertModes);
    }
}
