package it.polito.verefoo.vip.exception.common;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class StreamProcessingException extends RuntimeException {
    public StreamProcessingException() {
        super("Error while reading from input stream");
    }
}
