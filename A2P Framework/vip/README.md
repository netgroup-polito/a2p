# VIP - VEREFOO IDS/IPS Parser

---

## Description

VIP (VEREFOO IDS/IPS Parser) is a Spring Boot application featuring REST APIs that can parse the alerts generated
by certain IDS/IPS and translate them into input requirements for [VEREFOO](https://github.com/netgroup-polito/verefoo).

---

## API

### POST /api/parser/{idsName}/{idsVersion}/{alertMode}

VIP will select the correct parser based on `idsName` and `idsVersion` and try to parse the body to extract all the
relevant information using the chosen `alertMode`.
After that, it will generate the correct VEREFOO requirements and eliminate possible duplicates.

#### Example request

- `POST /api/parser/snort/3/AlertFastV0?priority=2`
- Request body:
    ```
  08/05-14:27:15.908164  [**] [1:2013504:6] ET TROJAN Observed Malicious SSL Cert (Likely Malware CnC Domain Related) [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 192.168.1.2:56340 -> 217.160.0.120:443
  08/05-14:27:19.428771  [**] [1:2014819:5] ET SCAN Behavioral Unusual Port 22 traffic Potential Scan or Inbound Attack [**] [Classification: Detection of a Network Scan] [Priority: 2] {TCP} 92.118.37.80:56834 -> 192.168.1.2:22
  08/05-14:30:20.534654  [**] [1:2001219:20] ET POLICY PE EXE or DLL Windows file download HTTP [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.2:56340 -> 104.20.1.85:80
  08/05-14:32:45.835122  [**] [1:2010935:3] ET TROJAN ELF/Mirai Variant User-Agent (Inbound) [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 192.168.1.2:56340 -> 217.160.0.120:443
    ```

#### Return value

An XML representation of the extracted VEREFOO rules:
```xml
<PropertyDefinition>
    <Property graph="0" name="IsolationProperty" src="192.168.1.2" dst="217.160.0.120" dst_port="443" lv4proto="TCP"/>
    <Property graph="0" name="IsolationProperty" src="92.118.37.80" dst="192.168.1.2" dst_port="22" lv4proto="TCP"/>
    <Property graph="0" name="IsolationProperty" src="192.168.1.2" dst="104.20.1.85" dst_port="80" lv4proto="TCP"/>
</PropertyDefinition>
```

#### Errors

- 404 (Not Found)
  - __ParserNotFoundException__: `idsName` and `idsVersion` combination does not exist
  - __AlertModeNotFoundException__: selected `alertMode` does not exist
- 400 (Bad Request)
  - __MalformedAlertException__: alert does not include required fields, contains inappropriate spacing or other formatting errors and the parser cannot extract any information
  - __ProtocolErrorException__ (Snort3-specific): alert contains `Error` as its protocol
  - __RequestPriorityException__: priority inside request parameter is not within range for the chosen parser
  - __AlertPriorityException__: priority inside alert is not within range for the chosen parser
  - __InvalidIPsException__: source or destination IPs are invalid (e.g. `192.168.1.256`)
  - __InvalidPortNumbersException__: alert contains port numbers that are not between 0 and 65535
  - __UnexpectedPortsException__: ports are provided for a protocol that does not require ports
  - __PortMismatchException__: one of the ports is missing
  - __SamePortTypeException__: alert contains ports that are both ephemeral or non-ephemeral
  - __UnsupportedAlertModeException__: `alertMode` is not supported for that specific `idsName` and `idsVersion` combination
  - __ConstraintViolationException__: when any of the request parameters fails to meet the specified constraints
- 500 (Internal Server Error)
  - __RequestStreamException__: an error occurred while getting the input stream from the request
  - __StreamProcessingException__: an error occurred while reading from the input stream
  - __StrategyNotSetException__: this happens when the strategy for the parser was not set
  prior to calling the `AbstractParserStrategy.parse()` method. It should only be thrown in tests because
  the strategy is always set inside the `ParserRegistry.getParser()` method before returning the requested parser
