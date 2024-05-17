package it.polito.verefoo.vip.model;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import it.polito.verefoo.vip.enums.Lv4proto;

import java.util.Objects;

public class Requirement {
    @JacksonXmlProperty(isAttribute = true)
    private final Integer graph;
    @JacksonXmlProperty(isAttribute = true)
    private final String name = "IsolationProperty";
    @JacksonXmlProperty(isAttribute = true)
    private final String src;
    @JacksonXmlProperty(isAttribute = true)
    private final String dst;
    @JacksonXmlProperty(isAttribute = true)
    private final Integer src_port;
    @JacksonXmlProperty(isAttribute = true)
    private final Integer dst_port;
    @JacksonXmlProperty(isAttribute = true)
    private final Lv4proto lv4proto;

    public Requirement(Integer graph, String src, String dst, Integer src_port, Integer dst_port, Lv4proto lv4proto) {
        this.graph = graph;
        this.src = src;
        this.dst = dst;
        this.src_port = src_port;
        this.dst_port = dst_port;
        this.lv4proto = lv4proto;
    }

    // equals and hashCode are needed to remove possible duplicates
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Requirement)) return false;
        Requirement that = (Requirement) o;
        return graph.equals(that.graph) && name.equals(that.name) && src.equals(that.src) && dst.equals(that.dst) &&
                Objects.equals(src_port, that.src_port) && Objects.equals(dst_port, that.dst_port) &&
                lv4proto == that.lv4proto;
    }

    @Override
    public int hashCode() {
        return Objects.hash(graph, name, src, dst, src_port, dst_port, lv4proto);
    }

    @Override
    public String toString() {
        return "Requirement{" +
                "graph=" + graph +
                ", name='" + name + '\'' +
                ", src='" + src + '\'' +
                ", dst='" + dst + '\'' +
                ", src_port=" + src_port +
                ", dst_port=" + dst_port +
                ", lv4proto=" + lv4proto +
                '}';
    }
}
