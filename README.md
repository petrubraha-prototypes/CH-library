# Cipher Encryption Library

A robust, modern Java-based library implementing well-known classical ciphers with a focus on clean architecture and best practices.

## 🚀 Features

The library provides implementations for the following ciphers:

- **Substitution Cipher**: Monoalphabetic character replacement.
- **Permutation Cipher**: Block-based character transposition.
- **Transposition Cipher**: Columnar transposition.
- **Affine Cipher**: Mathematical substitution using modular arithmetic.
- **Vigenere Cipher**: Polyalphabetic substitution using a keyword.

## 📦 Getting Started

### Prerequisites

- JDK 21 or higher
- Gradle (optional, `gradlew` wrapper included)

### Building the Project

```bash
./gradlew build
```

### Running the Demo

The library includes a demonstration in the `Library` class:

```bash
./gradlew run
```

### Running Tests

```bash
./gradlew test
```

## 📖 Usage Example

```java
import org.example.cipher.VigenereCipher;
import org.example.cipher.Cipher;

public class Example {
    public static void main(String[] args) {
        Cipher vigenere = new VigenereCipher("KEYWORD");
        String ciphertext = vigenere.encrypt("Hello World");
        String plaintext = vigenere.decrypt(ciphertext);
    }
}
```
