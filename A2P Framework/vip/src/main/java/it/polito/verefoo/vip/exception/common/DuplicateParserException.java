package it.polito.verefoo.vip.exception.common;

public class DuplicateParserException extends PriorityException {
    public DuplicateParserException(String idsName, String idsVersion) {
        super("Duplicate parser detected: " + idsName + ", version " + idsVersion);
    }
}
