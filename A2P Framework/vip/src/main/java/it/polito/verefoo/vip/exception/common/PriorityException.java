package it.polito.verefoo.vip.exception.common;

abstract class PriorityException extends RuntimeException {
    protected PriorityException(String message) {
        super(message);
    }
}
