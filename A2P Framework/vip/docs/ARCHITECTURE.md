# Software architecture documentation

---

## Introduction

### Purpose

The main goal of this document is to give a general overview of the architecture of VIP.
It describes the roles and functions of each component, highlights how they work together, 
and provides guidance on how the software can be extended in the future.

### Scope

- __Functional boundaries__
  - VIP features REST APIs to parse alerts from various IDS/IPS
  - It is capable of translating IDS/IPS alerts into input requirements for VEREFOO

- __API endpoints__
  - The primary API endpoint is `POST /api/parser/{idsName}/{idsVersion}/{alertMode}`
  - The alerts are sent inside the body of the request

- __Supported formats__
  - VIP can handle multiple alert modes, translating to different input formats
  - For instance, it can parse both plaintext (`alert_fast` mode of Snort) and JSON (`jsonout_output` mode of OSSEC)
  - The software is flexible and open to supporting other formats based on the alert modes of the integrated IDS/IPS

- __Extensibility__
  - VIP is designed to be easily extensible
  - It allows supporting any IDS/IPS in the market
  - Supporting a new IDS/IPS or alert mode is achievable by implementing specific abstract classes

- __Data handling__
  - The software can parse request bodies of any length, without a predefined limit

- __Technological stack__
  - The application is built using the Spring Boot framework (version 2.1.4.RELEASE, Java 1.8).

---

## Architectural overview

![VIP architecture](./img/vip_architecture.svg)

The diagram illustrates the main components of VIP and how they interact.

- **Upon startup**:
  - Parsers derived from `AbstractParser` register within the `ParserRegistry`
  - Strategies derived from `AbstractParserStrategy` also register in the `ParserRegistry`


- **The `ParserRegistry` maintains**:
  - A list of all supported parsers
  - A list of all supported strategies
  - A map associating each parser with the strategies it supports


- **When there's an incoming parsing request**:
  - The `parseAlerts()` method of `RequirementController` processes the request. Using the path variables
  `idsName`, `idsVersion`, and `alertMode`, this method determines the appropriate parser and strategy
  by invoking the `getParser()` and `getStrategy()` methods respectively


- **Subsequently**:
  - The `parse()` method of `AbstractParser` is executed. This method takes in:
    - The input stream containing the alerts
    - The minimum alert priority (which, if absent, corresponds to the default priority of the selected parser)
    - The graph ID (which, if absent, is set to 0)
    - The chosen parsing strategy
  - The `parse()` method of `AbstractParser` invokes the strategy's `parse()` method.
  It's supplied with the minimum alert priority and the parser's range of priority levels, namely `lowestPriorityLevel`
  and `highestPriorityLevel`


- **For the actual parsing**:
  - The logic resides in the `parse()` method of `AbstractParserStrategy`
  - Configuration options from `application.properties` are utilized in the parsing process
  and are accessed via the `ParserConfig` configuration class


- **Additionally**:
  - Parsers implementing the `AbstractParser` are annotated with `@SupportedStrategies`,
  which includes the class names of supported strategies derived from `AbstractParserStrategy`
  - It's noteworthy that strategies aren't strictly tied to a particular IDS or its version, allowing for potential reuse


- **Exception handling**:
  - Custom exceptions are found in the `exception` package
  - The `GlobalExceptionHandler` class deals with standard exceptions to ensure they're handled gracefully

---

## Main Components

### RequirementController

Handles the API endpoint `POST /api/parser/{idsName}/{idsVersion}/{alertMode}`. Upon receiving a request:
- The `parseAlerts()` method processes the request
- It returns a `RequirementSet`, which is automatically converted into an XML response with a `PropertyDefinition` root,
  encompassing all extracted `Property` nodes

### AbstractParser

An abstract representation of a parser. Features include:
- Abstract methods defining the IDS name, version, and its priority level range
- A `defaultPriority` attribute set during instantiation by child classes
- Capability to handle variable priority level definitions, where the numeric value of the lowest may be 
greater than the highest. The `shouldFilter` method accounts for these variations when processing alerts.
- A `parse()` method that, when called, invokes the `parse()` method of the `AbstractParserStrategy` 
passed as an argument, given that the strategy is not null

### AbstractParserStrategy

Represents the generic logic required to parse specific alert modes (e.g., the `alert_fast` mode in Snort). Key details:
- Holds a reference to `ParserConfig` (used by helper methods)
- Helper methods validate the alert for consistency, formatting, etc.
- The `parse()` method contains the actual parsing logic

### AbstractParserStrategy.ParsingContext

Nested within `AbstractParserStrategy`, this class:
- Contains details about the currently processed alert
- Serves as a central repository for all data,
allowing you to pass the context itself rather than multiple individual parameters

### @SupportedStrategies

An annotation used on classes derived from `AbstractParser` to specify the strategies supported by that particular parser.

### ParserConfig

A configuration class that provides access to configuration parameters within `application.properties` under the `vip` prefix.

### ParserRegistry

Serves as a repository for parsers and strategies. It maintains:
- A list of all parsers
- A list of all strategies
- A map connecting each parser to its supported strategies

Parsers and strategies can be registered using the `registerParser()` and `registerStrategy()` methods, respectively. 
To retrieve a specific parser, the `getParser()` method requires both `idsName` and `idsVersion` as parameters. 
Meanwhile, the `getStrategy()` method retrieves a strategy, given a supported `parser` and the specified `alertMode`.

---

## Extending VIP

To extend VIP, follow these steps:
1. **Create a new parser class**:
   - Create a subclass of `AbstractParser` in the `parser` package corresponding to the target IDS
   - Annotate it with `@Component`
   - Implement all abstract methods. This includes:
     - Specifying the parser's name and version and making sure they are unique.
     For POST requests to `/api/parser/{idsName}/{idsVersion}/{alertMode}`, the `idsName` and `idsVersion` in the URL
     map directly to the parser's name and version, ensuring the right parser class is retrieved
     - Setting the lowest and highest priority levels
     - Providing a default priority in the constructor, used when no priority level is specified in the request
2. **Create a new strategy class**:
   - Create one or more subclasses of `AbstractParserStrategy` in the `strategy` package corresponding to the target IDS
   - Make sure the names of the new strategy classes are unique
   - Annotate all strategy classes with `@Component`
   - Implement the `parse()` method. Use the helper methods for alert validation and maintain a local `ParsingContext`,
   updating it as soon as new information is extracted
3. **Annotate the parser class** with `@SupportedStrategies`, listing the strategies it supports, like so:
`@SupportedStrategies({"StrategyClass1", "StrategyClass2", ...})`

As mentioned earlier, when making a POST request to `/api/parser/{idsName}/{idsVersion}/{alertMode}`,
`idsName` and `idsVersion` match the name and version of the parser class,
whereas `alertMode` matches the name of the strategy class (everything is case-insensitive).

For parsers of the same IDS, if there are common classes, attributes, or methods that might be used across 
multiple parsers, consider placing them in a utility class, such as `SnortUtils` for Snort.