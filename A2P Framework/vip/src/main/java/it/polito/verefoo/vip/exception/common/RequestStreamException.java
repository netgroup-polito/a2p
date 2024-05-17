package it.polito.verefoo.vip.exception.common;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class RequestStreamException extends RuntimeException {
    public RequestStreamException() {
        super("Error obtaining input stream from request");
    }
}
