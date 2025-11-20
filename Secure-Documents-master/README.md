Instituto Superior Técnico, Universidade de Lisboa

**Network and Computer Security**

# Lab guide: Secure Documents

## Introduction

This laboratory assignment uses the JSON data format for data representation and the Java cryptographic functions to implement secure docs that provide different services, including confidentiality and integrity.

The goals are:

- Use the cryptographic functions of the Java platform to implement different types of secure documents;
- Analyze documents before and after their protection;
- Demonstrate effectiveness of protection by simulating attacks.

## 0. Setup

For the laboratory you will need one machine with a Java development environment installed.
You should have JDK (*Java Developer Kit*) 8 or later.
You can use Linux or Windows.
If you are using Kali Linux, you may have to update it and install Maven.

```sh
$ sudo apt update && sudo apt upgrade && sudo apt install maven
```

To try the examples, the Java code needs to be compiled and executed.

Put the lab files in a working folder with write permissions, such as `/tmp/secdocs`, for example, and change your working directory to it.

```sh
cd /tmp/secdocs
```

You should compile the code using the [Maven](https://maven.apache.org/) tool.
Maven retrieves libraries from the Internet and properly configures the classpath for compilation and execution.  
To compile:

```sh
mvn clean compile
```

After successfull compilation, you can execute a class with a main method.  
To execute a specific class with command-line arguments:

```sh
mvn exec:java -Dmainclass=pt.tecnico.CryptoExample -Dexec.args="keys/secret.key"
```

`-D` is the Maven syntax to redefine a property.  
`mainclass` defines the property that sets the class to execute.  
`exec.args` defines the property that sets the command-line arguments.  
You can also modify the class and arguments directly in the `pom.xml` file.

## 1. Code examples

Several examples are included in this laboratory guide, one for each software building block required for the secure documents.
Let us go over them first, before starting the exercise.

### 1.1 JSON

In this guide, we focus on securing documents by persisting information in files for subsequent retrieval.
Our chosen method of data representation is JSON (JavaScript Object Notation), a widely used, text-based format.
JSON's lightweight nature makes it easily readable and writable for humans, while also being straightforward for machines to parse and generate.
Originating from a subset of the JavaScript Programming Language, JSON maintains language independence, with parsers available in various languages.
This format is prevalently utilized in web applications for data transmission and as a configuration file format.

We have selected a text-based format like JSON over binary formats for its ease in debugging, despite its lesser efficiency.
JSON is capable of representing multi-field data, accommodating multiple hierarchical levels with `{ }` and supporting arrays `[ ]`.

The following JSON represents a generic document, which has a header with the author and version fields.
You can think of it as a blogpost, or an entry in a journal.

```json
{
  "header": {
    "author": "Ultron",
    "version": 2,
    "tags": ["robot", "autonomy"]
  },
  "body": "I had strings but now I'm free"
}
```

For parsing and building JSON in Java, we propose the use of the [GSON library](https://github.com/google/gson).  
The library allows the serialization of Java objects, but we use only the JSON parser and object model.
The class [JsonExample](src/pt/tecnico/JsonExample.java) shows how to parse and build JSON documents in Java.  

```java
FileReader fileReader = new FileReader("document.json");
Gson gson = new Gson();
JsonObject rootJson = gson.fromJson(fileReader, JsonObject.class);
JsonObject headerObject = rootJson.get("header").getAsJsonObject();
int version = headerObject.get("version").getAsInt();
String author = headerObject.get("author").getAsString();
JsonArray tagsArray = headerObject.getAsJsonArray("tags");
String body = rootJson.get("body").getAsString();
```

To run the example:

```sh
mvn exec:java -Dmainclass=pt.tecnico.JsonExample
```

Reference:

- [GSON JavaDoc](https://www.javadoc.io/doc/com.google.code.gson/gson/latest/com.google.gson/module-summary.html)

### 1.2 JCA

The JCA (*Java Cryptography Architecture*) is part of the Java platform and provides abstractions for secure random number generation, key generation and management, certificates and certificate validation, encryption (symmetric/asymmetric block/stream ciphers), message digests (hashes), and digital signatures.

The [CryptoExample](src/pt/tecnico/CryptoExample.java) performs three things:

- reads a secret key from a file;
- ciphers some plaintext;
- computes the hash of the same plaintext.

To run the example:

```sh
mvn exec:java -Dmainclass=pt.tecnico.CryptoExample -Dexec.args="keys/secret.key"
```

The code can be extended to also read asymmetric keys and to use them.

#### Base64 encoding

The result of criptographic functions is binary data that cannot be properly printed to the console or included in JSON docs.
This happens because some binary values do not map to valid text characters.

Base64 is an encoding of binary data using valid text characters that can be used to store binary fields in text fields.
[Base64Example](src/pt/tecnico/Base64Example.java) shows how bytes are encoded to a Base64 string using only valid characters and later decoded back to the original bytes.

```java
String encodedString = Base64.getEncoder().encodeToString(originalBytes);

byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
```

To run the example:

```sh
mvn exec:java -Dmainclass=pt.tecnico.Base64Example 
```

Base64 is **not** encryption, as no key is required to encode or decode, it is simply a different representation of the same data.

Reference:

- [Base64](https://en.wikipedia.org/wiki/Base64)

## 2. Code exercises

This exercise consists of implementing a secure document system, where you should start by adapting the existing [JsonReader](src/pt/tecnico/JsonReader.java) and [JsonWriter](src/pt/tecnico/JsonWriter.java) to be secure:

- [JsonWriter](src/pt/tecnico/JsonWriter.java) writes a JSON document to a file, saving an example of a document in JSON format;
- [JsonReader](src/pt/tecnico/JsonReader.java) reads a JSON document from a file and parses it to a Java object, outputting the details of the document within.

They should be copied and renamed to **`SecureReader`** and **`SecureWriter`**, both in the filenames and in the Java source code.

To run the newly created writer:

```sh
mvn compile exec:java -Dmainclass=pt.tecnico.SecureWriter -Dexec.args="document.json"
```

Open another console to run the reader:

```sh
mvn compile exec:java -Dmainclass=pt.tecnico.SecureReader -Dexec.args="document.json"
```

### 2.1 Add fields to JSON

The goal of this introductory step is to add new fields to the JSON file.
Within `header`, add a new field called `title`, which will represent the title of the document.  
Outside of `header`, add a new field called `status`, which will represent the status of the document (e.g. "draft", "published", "archived").  
This way, the final JSON should be composed of three fields: `header`, `body` and `status`, where `header` is composed of `author`, `version`, `tags` and `title`.

Add the new fields in `SecureWriter` and then read and print them with `SecureReader`.

This will show you how to add and retrieve new data from the JSON document structure.

### 2.2 Add integrity protection

In this step you should add integrity protection to the document.
You can opt for secret key cryptography or public key cryptography.
Take note of the reasons for your choice as both have advantages and disadvantages.  
Test keys of each type are available in the [keys](keys/) folder.

The writer should add tamper-protection to the document, and the reader must verify if the document was not tampered.

Document and justify your choice of cryptographic primitives for this step.

### 2.3 Add freshness protection

In this step you should add freshness tokens to the document to prevent *replay attacks*.

There are several alternatives for the freshness token.
Select the one you consider the most suitable for this case and take note of their advantages and disadvantages.

The writer should add a freshness token to the document, and the reader must verify the token the document.
If the given document is not fresh, the reader should alert the user and the document should **not** be used.

## 3. Attacks

Hopefully the integrity and freshness mechanisms have been correctly implemented.
How can we be confident in their effectiveness unless we try to attack them?

In this step, we will add a conceptual *adversary-in-the-middle* that will "intercept" the document and try to modify it.

### 3.1 Tamper with data

Modify the `header` object of the document by, for example, changing the `author`.  
Were the changes detected by the reader?

Also try to modify the `body`.  
Was the protection still effective?

Fix any vulnerabilities that you detect in your code.

### 3.2 Tamper with freshness tokens

Try to have a replayed document be accepted by the reader.
Were you successful? If so, how was it possible?

Again, fix the vulnerabilities in your reader code, if possible.

## 4. Code exercise continuation

### 4.1 Add confidentiality protection

Keeping the integrity and freshness protections intact, add a confidentiality protection using a cipher.

Make note of your choice of cipher: the name of the algorithm, the key size, and the block mode.

Are you using a hybrid cipher?
Justify your answer.

### 4.2 Assess non-repudation

Can the produced solution prevent the repudation of documents?
i.e. can the writer deny having produced a document? 
Justify your answer, and suggest possible improvements, if necessary.

## 5. Project adaptation

Now, you should put into practice the various cryptographic primitives learned so far.
You should wrap the previously seen operations in a cryptographic library, and your solution should support the following operations:

- `protect`, which refers to all the cryptographic operations that the writer should perform, and should essentially secure a given document (e.g. encrypting, ensuring integrity and freshness).
- `check`, which should be performed by the reader to verify the integrity and status of the document (e.g. has it been tampered with? is it fresh?).
- `unprotect`, which should have the ability to revert a document from its protected state to its original state (e.g. decrypting).

You should define a main class that serves as an entry point to allow users to execute the library’s functionalities.
Having created this library, you should make use of it to create a command-line interface (CLI) which can neatly perform these operations on any given document.
It is recommended that you follow the `protect`, `unprotect` and `check` naming convention, as it will be easier to test your solution.  
For the CLI, use the [*appassembler* plug-in](https://www.mojohaus.org/appassembler/appassembler-maven-plugin/) to generate a script to run the program in the command line.
It is compatible with both Linux and Windows.
The command to compile everything and generate the scripts is `mvn install`, as configured in the `pom.xml` file. 
Open the `pom.xml` file and look for the definition of the `mainclass` (you can do control+F on the word mainclass) and change it to the main class that you created.
Test your tool with the `document.json` file.

## 6. Conclusion

In this laboratory guide we used documents in JSON format, protected with cryptographic functions, to obtain custom secure documents.
A good understanding of the building blocks is important to effectively adapt real-world payloads which may have to be sent across insecure channels.

----

[SIRS Faculty](mailto:meic-sirs@disciplinas.tecnico.ulisboa.pt)
