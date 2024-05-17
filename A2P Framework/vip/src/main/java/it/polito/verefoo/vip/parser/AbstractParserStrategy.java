package it.polito.verefoo.vip.parser;

import it.polito.verefoo.vip.config.ParserConfig;
import it.polito.verefoo.vip.enums.Lv4proto;
import it.polito.verefoo.vip.exception.common.*;
import it.polito.verefoo.vip.model.Requirement;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.util.Set;
import java.util.regex.Pattern;

public abstract class AbstractParserStrategy {
    @Autowired
    private ParserRegistry parserRegistry;

    private final ParserConfig parserConfig;

    // IP_PATTERN is declared as static, so I don't have to compile it everytime checkAlert() is called
    private static final Pattern IP_PATTERN = Pattern.compile("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$");

    @Autowired
    public AbstractParserStrategy(ParserConfig parserConfig) {
        this.parserConfig = parserConfig;
    }

    @PostConstruct
    public void registerStrategy() {
        parserRegistry.registerStrategy(this);
    }

    public abstract Set<Requirement> parse(InputStream inputStream, int priority, int graph, int lowestPriorityLevel, int highestPriorityLevel);

    protected boolean shouldFilter(ParsingContext context, int priority, int lowestPriorityLevel, int highestPriorityLevel) {
        int alertPriority = context.getAlertPriority();

        // highest priority level is not always the highest number
        // snort's priority levels range from 1 to 2147483647, with 1 being the most severe
        int lowerBound = Math.min(lowestPriorityLevel, highestPriorityLevel);
        int upperBound = Math.max(lowestPriorityLevel, highestPriorityLevel);

        // check if the priority provided as a request parameter is valid or not
        if (priority < lowerBound || priority > upperBound) {
            throw new RequestPriorityException(priority, lowestPriorityLevel, highestPriorityLevel);
        }

        // check if the priority inside the alert is valid or not
        if (alertPriority < lowerBound || alertPriority > upperBound) {
            throw new AlertPriorityException(context, lowestPriorityLevel, highestPriorityLevel);
        }

        if (lowestPriorityLevel < highestPriorityLevel) {
            return alertPriority < priority;
        } else {
            return alertPriority > priority;
        }
    }

    private boolean isPortNumberOutOfRange(Integer port) {
        return port < 0 || port > 65535;
    }

    // some operating systems, like many Linux-based ones, do not comply with standard ephemeral port numbering
    private boolean isEphemeral(Integer port) {
        return port >= 32768;
    }

    protected void checkAlert(ParsingContext context) {
        String src = context.getSrc();
        String dst = context.getDst();
        Integer src_port = context.getSrcPort();
        Integer dst_port = context.getDstPort();
        Lv4proto lv4proto = context.getLv4proto();

        if (!IP_PATTERN.matcher(src).matches() || !IP_PATTERN.matcher(dst).matches()) {
            throw new InvalidIPsException(context);
        }

        if ((src_port != null && isPortNumberOutOfRange(src_port)) || (dst_port != null && isPortNumberOutOfRange(dst_port))) {
            throw new InvalidPortNumbersException(context);
        }

        if (lv4proto == Lv4proto.OTHER && (src_port != null || dst_port != null)) {
            throw new UnexpectedPortsException(context);
        }

        if ((src_port == null && dst_port != null) || (src_port != null && dst_port == null)) {
            throw new PortMismatchException(context);
        }

        if (!parserConfig.isAllowSamePortType() && src_port != null &&
                ((!isEphemeral(src_port) && !isEphemeral(dst_port)) ||
                        (isEphemeral(src_port) && isEphemeral(dst_port)))) {
            throw new SamePortTypeException(context);
        }
    }

    protected void removeEphemeralPorts(ParsingContext context) {
        Integer src_port = context.getSrcPort();
        Integer dst_port = context.getDstPort();

        if (src_port == null) {
            return;
        }

        if (isEphemeral(src_port)) {
            context.setSrcPort(null);
        }

        if (isEphemeral(dst_port)) {
            context.setDstPort(null);
        }
    }

    // contains all info about the alert that is currently being parsed
    // its main purpose is to have everything in one place and avoid passing
    // parameters around when performing checks
    public static class ParsingContext {
        private String alertString;
        private int alertPriority;
        private Integer graph;
        private String src;
        private String dst;
        private Integer dst_port;
        private Integer src_port;
        private Lv4proto lv4proto;

        public void setAlertString(String alertString) {
            int MAX_LENGTH = 500;

            if (alertString == null) {
                this.alertString = "";
                return;
            }

            // need to remove control characters, otherwise it causes problems with console logs
            alertString = alertString.replaceAll("[\\x00-\\x1F]", " ").trim();

            // truncate to MAX_LENGTH to avoid having long error messages
            if (alertString.length() > MAX_LENGTH) {
                alertString = alertString.substring(0, MAX_LENGTH) + "...";
            }

            this.alertString = alertString;
        }

        public String getAlertString() {
            return alertString;
        }

        public int getAlertPriority() {
            return alertPriority;
        }

        public void setAlertPriority(int alertPriority) {
            this.alertPriority = alertPriority;
        }

        public void setGraph(Integer graph) {
            this.graph = graph;
        }

        public String getSrc() {
            return src;
        }

        public void setSrc(String src) {
            this.src = src;
        }

        public String getDst() {
            return dst;
        }

        public void setDst(String dst) {
            this.dst = dst;
        }

        public Integer getDstPort() {
            return dst_port;
        }

        public void setDstPort(Integer dst_port) {
            this.dst_port = dst_port;
        }

        public Integer getSrcPort() {
            return src_port;
        }

        public void setSrcPort(Integer src_port) {
            this.src_port = src_port;
        }

        public Lv4proto getLv4proto() {
            return lv4proto;
        }

        public void setLv4proto(Lv4proto lv4proto) {
            this.lv4proto = lv4proto;
        }

        public Requirement toRequirement() {
            return new Requirement(graph, src, dst, src_port, dst_port, lv4proto);
        }
    }
}
