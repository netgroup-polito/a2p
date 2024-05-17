package it.polito.verefoo.vip.enums;

public enum Lv4proto {
    ANY("ANY"),
    OTHER("OTHER"),
    TCP("TCP"),
    UDP("UDP");

    private final String name;

    Lv4proto(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
