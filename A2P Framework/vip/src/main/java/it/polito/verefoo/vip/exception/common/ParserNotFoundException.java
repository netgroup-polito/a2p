package it.polito.verefoo.vip.exception.common;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class ParserNotFoundException extends RuntimeException {
    public ParserNotFoundException(String idsName, String idsVersion) {
        super("No available parser for " + idsName + ", version " + idsVersion);
    }
}
