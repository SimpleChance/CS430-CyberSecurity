# bf_jcrypt

Java-based rule-driven BFS password cracking tool built around the Unix DES `crypt` hashing algorithm.

This program loads a password file, extends a dictionary using user name data, applies structured mutation rule chains, and compares generated candidates against stored hashes using the provided salt.

---

### Features

- Parses Unix-style password files
- Extracts salts from hashed passwords
- Extends dictionary with user-specific name data
- Applies configurable rule chains for candidate mutation
- Supports:
  - Case transformations
  - Reversal and reflection
  - Character deletion
  - Digit and symbol prefix/suffix
  - Character insertion at all positions
  - Leetspeak branching replacements
- Writes cracked credentialsand other data to output file

---

### How It Works

### Unix DES crypt

Passwords are verified using:

    jcrypt.crypt(salt, candidate)

Important properties:

- Only the first 8 characters of a password affect the hash
- The first 2 characters of the stored hash are the salt
- The salt must be reused when verifying candidates

### Rule-Based Mutation Engine

Instead of brute-forcing all possible strings, the program:

1. Loads a dictionary file
2. Extends it with user name variations
3. Applies rule chains to generate candidate mutations
4. Hashes each candidate with the user's salt
5. Compares the result against the stored hash

This approach reduces search space while targeting realistic password patterns.

---

### Rule Categories

The rule engine supports:

- Case normalization
- Digit prefix/suffix combinations
- Symbol prefix/suffix combinations
- Multi-digit combinations
- Structural edits (reverse, delete, duplicate, reflect)
- Charset insertions (lowercase, uppercase, digits, symbols)
- Leetspeak branching replacements

Rules are organized into ordered chains.

---

### Project Structure

```
.
├── bf_crypt.java 
├── jcrypt.java
├── wordlist.txt
├── passwd.txt
├── passwd1.txt
├── Results/
```

---

### Requirements

- Java 8 or higher

---

### Compilation

    javac bf_jcrypt.java jcrypt.java

---

### Usage

    java bf_jcrypt <passwd_file> <dictionary_file>

Example:

    java bf_jcrypt passwd1.txt words.txt

Output is written to:

    Results/<passwd_file>_results.txt

---

### Implementation Design

### Data Structures

- `UserEntry` stores user metadata and hash
- `Operation` represents a single mutation operator
- `Rule` groups one or more operations
- `RULE_CHAINS` defines ordered mutation pipelines

### Dictionary Extension

For each user, the dictionary is expanded with:

- First name
- Last name
- First + last
- Last + first
- Initial + name combinations

This increases success rates for name-based passwords.

### Limitations

- Rule-based approach only (not full brute-force)
- Performance depends on rule ordering

---

### Final Notes

Not fully optimized (I couldn't hit the last handful of passwords and ended up adding lot's of useless rulechains to try and hit them). AI was used to help with Java builtins and some syntax, as well as markdown syntax for this README.md file.

---

### Author

Chance Jewell  
CS340 Password Cracking Assignment