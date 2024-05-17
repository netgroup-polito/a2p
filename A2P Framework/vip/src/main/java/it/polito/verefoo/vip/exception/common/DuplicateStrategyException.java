package it.polito.verefoo.vip.exception.common;

public class DuplicateStrategyException extends PriorityException {
    public DuplicateStrategyException(String strategyName) {
        super("Duplicate strategy detected: " + strategyName);
    }
}
