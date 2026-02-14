/*
bf_jcrypt.java

Rule-based password cracking tool built around the Unix DES crypt() algorithm.

Loads a password file, extends a dictionary with user name data,
applies structured mutation rule chains, and compares generated
candidates against stored hashes using jcrypt.

CS340 - Password Cracking Assignment
*/

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;


public class bf_jcrypt {

    /* Data Structures */

    /*
    Represents a single user entry from the password file.
    Stores username, name components, salt, and full hash.
    */
    static class UserEntry {
        String username;
        String firstname;
        String lastname;
        String salt;
        String hash;
    }


    /*
    Enumeration of all supported mutation operations.
    */
    enum OpCode {
        IDENTITY,

        /* Case transformations */
        LOWERCASE_ALL,
        CAPITALIZE_FIRST,
        CAPITALIZE_ALL,
        NCAPITALIZE,
        TOGGLE_CASE,

        /* Structural operations */
        REVERSE,
        DUPLICATE,
        REFLECT_FRONT,
        REFLECT_BACK,

        /* Deletion operations */
        DELETE_FIRST,
        DELETE_LAST,

        /* Charset-based expansions */
        APPEND_CHARSET,
        PREPEND_CHARSET,
        INSERT_CHARSET,

        /* Character replacement */
        REPLACE
    }


    /*
    Represents a single mutation operation.
    Some operations require additional arguments
    (e.g., character sets or replacement characters).
    */
    static class Operation {
        OpCode code;
        String strArg;
        char charArg1;
        char charArg2;

        Operation(OpCode code){
            this.code = code;
        }

        Operation(OpCode code, String strArg) {
            this.code = code;
            this.strArg = strArg;
        }

        Operation(OpCode code, char from, char to) {
            this.code = code;
            this.charArg1 = from;
            this.charArg2 = to;
        }
    }


    /* Character sets used for expansion rules */

    static final String DIGITS = "0123456789";
    static final String LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    static final String SPECIALS = "!@#$%^&*()-_+=~/`[]{}|:;\"'<>,.?\\\\";
    static final String UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";


    /*
    Rule represents a sequence of operations.
    Multiple rules are combined into rule chains.
    */
    enum Rule {

        /* Baseline */
        IDENTITY(new Operation(OpCode.IDENTITY)),

        /* Case operations */
        LOWERCASE_ALL(new Operation(OpCode.LOWERCASE_ALL)),
        CAPITALIZE_FIRST(new Operation(OpCode.CAPITALIZE_FIRST)),
        CAPITALIZE_ALL(new Operation(OpCode.CAPITALIZE_ALL)),
        NCAPITALIZE(new Operation(OpCode.NCAPITALIZE)),
        TOGGLE_CASE(new Operation(OpCode.TOGGLE_CASE)),

        /* Structural operations */
        REVERSE(new Operation(OpCode.REVERSE)),
        DUPLICATE(new Operation(OpCode.DUPLICATE)),
        REFLECT_FRONT(new Operation(OpCode.REFLECT_FRONT)),
        REFLECT_BACK(new Operation(OpCode.REFLECT_BACK)),

        /* Deletions */
        DELETE_FIRST(new Operation(OpCode.DELETE_FIRST)),
        DELETE_LAST(new Operation(OpCode.DELETE_LAST)),

        /* Charset expansions */
        APPEND_LOWER(new Operation(OpCode.APPEND_CHARSET, LOWERCASE_CHARS)),
        APPEND_UPPER(new Operation(OpCode.APPEND_CHARSET, UPPERCASE_CHARS)),
        APPEND_SPECIAL(new Operation(OpCode.APPEND_CHARSET, SPECIALS)),
        APPEND_DIGIT(new Operation(OpCode.APPEND_CHARSET, DIGITS)),

        PREPEND_LOWER(new Operation(OpCode.PREPEND_CHARSET, LOWERCASE_CHARS)),
        PREPEND_UPPER(new Operation(OpCode.PREPEND_CHARSET, UPPERCASE_CHARS)),
        PREPEND_SPECIAL(new Operation(OpCode.PREPEND_CHARSET, SPECIALS)),
        PREPEND_DIGIT(new Operation(OpCode.PREPEND_CHARSET, DIGITS)),

        INSERT_LOWER(new Operation(OpCode.INSERT_CHARSET, LOWERCASE_CHARS)),
        INSERT_UPPER(new Operation(OpCode.INSERT_CHARSET, UPPERCASE_CHARS)),
        INSERT_DIGIT(new Operation(OpCode.INSERT_CHARSET, DIGITS)),
        INSERT_SPECIAL(new Operation(OpCode.INSERT_CHARSET, SPECIALS)),

        /* Leetspeak replacements */
        LEET_A(new Operation(OpCode.REPLACE, 'a', '@')),
        LEET_O(new Operation(OpCode.REPLACE, 'o', '0')),
        LEET_E(new Operation(OpCode.REPLACE, 'e', '3')),
        LEET_S(new Operation(OpCode.REPLACE, 's', '$'));

        final List<Operation> operations = new ArrayList<>();

        Rule(Operation... ops) {
            for (Operation op : ops) {
                operations.add(op);
            }
        }
    }


    /*
    Ordered rule chains applied to each dictionary candidate.
    Rules are grouped by likelihood and expansion cost.
    */
    static final Rule[][] RULE_CHAINS = {
        /* 0. No modification (baseline) */
        { Rule.IDENTITY },
        
        /* 1. Case normalization */
        { Rule.LOWERCASE_ALL },
        { Rule.CAPITALIZE_ALL },
        { Rule.CAPITALIZE_FIRST },
        { Rule.NCAPITALIZE },
        { Rule.TOGGLE_CASE },
        
        /* 2. Single digit suffix / prefix */
        { Rule.LOWERCASE_ALL, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.APPEND_DIGIT },
        { Rule.LOWERCASE_ALL, Rule.PREPEND_DIGIT },
        
        /* 3. Multi digit suffix and prefix (birth years, repeats) */
        { Rule.LOWERCASE_ALL, Rule.APPEND_DIGIT, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.APPEND_DIGIT, Rule.APPEND_DIGIT },
        { Rule.LOWERCASE_ALL, Rule.PREPEND_DIGIT, Rule.PREPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.PREPEND_DIGIT, Rule.PREPEND_DIGIT },
        { Rule.LOWERCASE_ALL, Rule.PREPEND_DIGIT, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.PREPEND_DIGIT, Rule.APPEND_DIGIT },
        { Rule.LOWERCASE_ALL, Rule.APPEND_DIGIT, Rule.APPEND_DIGIT, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.APPEND_DIGIT, Rule.APPEND_DIGIT, Rule.APPEND_DIGIT },
        { Rule.LOWERCASE_ALL, Rule.PREPEND_DIGIT, Rule.PREPEND_DIGIT, Rule.PREPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.PREPEND_DIGIT, Rule.PREPEND_DIGIT, Rule.PREPEND_DIGIT },
        /* 3b. Reversed + digit suffix */
        { Rule.REVERSE, Rule.APPEND_DIGIT },
        { Rule.REVERSE, Rule.APPEND_DIGIT, Rule.APPEND_DIGIT },
        /* 3c. Deleted last char + digit suffix */
        { Rule.DELETE_LAST, Rule.APPEND_DIGIT },
        { Rule.DELETE_LAST, Rule.APPEND_DIGIT, Rule.APPEND_DIGIT },
        /* 3d. Special char + digit suffix */
        { Rule.CAPITALIZE_FIRST, Rule.APPEND_SPECIAL, Rule.APPEND_DIGIT },
        { Rule.LOWERCASE_ALL, Rule.APPEND_SPECIAL, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.APPEND_DIGIT, Rule.APPEND_SPECIAL },
        { Rule.LOWERCASE_ALL, Rule.APPEND_DIGIT, Rule.APPEND_SPECIAL },
        
        /* 4. Common symbol suffix / prefix */
        { Rule.LOWERCASE_ALL, Rule.APPEND_SPECIAL },
        { Rule.CAPITALIZE_FIRST, Rule.APPEND_SPECIAL },
        { Rule.LOWERCASE_ALL, Rule.PREPEND_SPECIAL },

        /* 5. Leetspeak (branching replacements) */ 
        { Rule.LOWERCASE_ALL, Rule.LEET_A },
        { Rule.LOWERCASE_ALL, Rule.LEET_E },
        { Rule.LOWERCASE_ALL, Rule.LEET_O },
        { Rule.LOWERCASE_ALL, Rule.LEET_S },
        { Rule.LEET_A, Rule.LOWERCASE_ALL },
        { Rule.LEET_S, Rule.LOWERCASE_ALL },
        { Rule.LEET_E, Rule.LOWERCASE_ALL }, 
        { Rule.LEET_O, Rule.LOWERCASE_ALL },
        { Rule.LOWERCASE_ALL, Rule.LEET_A, Rule.LEET_S, Rule.LEET_E, Rule.LEET_O },
        { Rule.LEET_A, Rule.LEET_S, Rule.LEET_E, Rule.LEET_O, Rule.LOWERCASE_ALL },

        /* 6. Case + leet + digit */
        { Rule.CAPITALIZE_FIRST, Rule.LEET_A, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.LEET_S, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.LEET_E, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.LEET_O, Rule.APPEND_DIGIT },

        /* 7. Structural edits */
        { Rule.DELETE_FIRST },
        { Rule.DELETE_LAST },
        { Rule.REVERSE },

        /* 8. Duplication & reflection */
        { Rule.DUPLICATE },
        { Rule.DUPLICATE, Rule.REVERSE },
        { Rule.DUPLICATE, Rule.APPEND_DIGIT },
        { Rule.REFLECT_FRONT },
        { Rule.REFLECT_BACK },
        { Rule.REFLECT_BACK, Rule.APPEND_DIGIT },
        { Rule.REFLECT_FRONT, Rule.APPEND_DIGIT },
        
        /* 9. Exotic / low probability (kept last) basically I'm just grasping for straws here*/
        { Rule.TOGGLE_CASE, Rule.APPEND_DIGIT },
        { Rule.NCAPITALIZE, Rule.APPEND_SPECIAL },
        { Rule.LOWERCASE_ALL, Rule.APPEND_LOWER },
        { Rule.LOWERCASE_ALL, Rule.APPEND_UPPER },
        { Rule.CAPITALIZE_FIRST, Rule.APPEND_LOWER },
        { Rule.CAPITALIZE_FIRST, Rule.APPEND_UPPER },
        { Rule.LOWERCASE_ALL, Rule.INSERT_DIGIT },
        { Rule.LOWERCASE_ALL, Rule.INSERT_SPECIAL },
        { Rule.CAPITALIZE_FIRST, Rule.INSERT_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.INSERT_SPECIAL },
        { Rule.LOWERCASE_ALL, Rule.INSERT_LOWER },
        { Rule.LOWERCASE_ALL, Rule.INSERT_UPPER },
        { Rule.CAPITALIZE_FIRST, Rule.INSERT_LOWER },
        { Rule.CAPITALIZE_FIRST, Rule.INSERT_UPPER },
        { Rule.LOWERCASE_ALL, Rule.PREPEND_LOWER },
        { Rule.LOWERCASE_ALL, Rule.PREPEND_UPPER },
        { Rule.CAPITALIZE_FIRST, Rule.PREPEND_LOWER },
        { Rule.CAPITALIZE_FIRST, Rule.PREPEND_UPPER },
    };


    /*
    Loads password entries from a Unix-style password file.
    Extracts salt and name components.
    */
    static List<UserEntry> loadPasswordFile(String filename) throws Exception {
        List<UserEntry> users = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length < 2) continue;

                UserEntry u = new UserEntry();
                u.username = parts[0];
                u.hash = parts[1];
                u.salt = (u.hash != null && u.hash.length() >= 2) ? u.hash.substring(0, 2) : "";

                if (parts.length > 4 && parts[4] != null && !parts[4].isBlank()) {
                    String[] nameParts = parts[4].split(" ");
                    u.firstname = nameParts.length > 0 ? nameParts[0] : "";
                    u.lastname = nameParts.length > 1 ? nameParts[1] : "";
                } else {
                    u.firstname = "";
                    u.lastname = "";
                }

                users.add(u);
            }
        }
        return users;
    }


    /*
    Loads dictionary words into memory.
    */
    static List<String> loadDictionary(String filename) throws Exception {
        List<String> words = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.isBlank()) {
                    words.add(line.trim());
                }
            }
        }
        return words;
    }


    /*
    Extends dictionary with user-specific name variants.
    */
    static List<String> addNameDatatoDictionary(UserEntry user, List<String> dictionary) {
        List<String> extended = new ArrayList<>(dictionary);

        extended.add(user.firstname);
        extended.add(user.lastname);
        extended.add(user.firstname + user.lastname);
        extended.add(user.lastname + user.firstname);
        extended.add(user.firstname.charAt(0) + user.lastname);
        extended.add(user.firstname + user.lastname.charAt(0));
        extended.add(user.lastname.charAt(0) + user.firstname);
        extended.add(user.lastname + user.firstname.charAt(0));

        return extended;
    }


    /*
    Applies a single operation to a list of inputs.
    Some operations generate one result per input,
    others branch heavily (e.g., charset insertion).
    */
    static List<String> applyOperationToList(List<String> inputs, Operation op) {
        List<String> outputs = new ArrayList<>();
        switch (op.code) {
            case IDENTITY:
                outputs.addAll(inputs);
                break;
            
            case LOWERCASE_ALL:
                for (String w : inputs) outputs.add(w.toLowerCase());
                break;

            case CAPITALIZE_FIRST:
                for (String w : inputs) {
                    if (w.length() > 0) outputs.add(Character.toUpperCase(w.charAt(0)) + w.substring(1));
                    else outputs.add(w);
                }
                break;

            case CAPITALIZE_ALL:
                for (String w : inputs) outputs.add(w.toUpperCase());
                break;
            
            case NCAPITALIZE:
                for (String w : inputs) {
                    if (w.length() > 0) {
                        outputs.add(
                            Character.toLowerCase(w.charAt(0)) +
                            w.substring(1).toUpperCase()
                        );
                    }
                }
                break;
            
            case TOGGLE_CASE:
                for (String w : inputs) {
                    StringBuilder sb = new StringBuilder();
                    boolean upper = true;

                    for (char c : w.toCharArray()) {
                        if (Character.isLetter(c)) {
                            sb.append(
                                upper ? Character.toUpperCase(c)
                                    : Character.toLowerCase(c)
                            );
                            upper = !upper;
                        } else {
                            sb.append(c);
                        }
                    }
                    outputs.add(sb.toString());
                }
                break;

            case REVERSE:
                for (String w : inputs) outputs.add(new StringBuilder(w).reverse().toString());
                break;
            
            case DUPLICATE:
                for (String w : inputs) {
                    outputs.add(w + w);
                }
                break;
            
            case REFLECT_FRONT:
                for (String w : inputs) {
                    String r = new StringBuilder(w).reverse().toString();
                    outputs.add(w + r);
                }
                break;
            
            case REFLECT_BACK:
                for (String w : inputs) {
                    String r = new StringBuilder(w).reverse().toString();
                    outputs.add(r + w);
                }
                break;
            
            case DELETE_FIRST:
                for (String w : inputs) {
                    if (w.length() > 0) {
                        outputs.add(w.substring(1));
                    }
                }
                break;

            case DELETE_LAST:
                for (String w : inputs) {
                    if (w.length() > 0) {
                        outputs.add(w.substring(0, w.length() - 1));
                    }
                }
                break;

            case APPEND_CHARSET:
                for (String w : inputs) {
                    for (char c : op.strArg.toCharArray()) outputs.add(w + c);
                }
                break;

            case PREPEND_CHARSET:
                for (String w : inputs) {
                    for (char c : op.strArg.toCharArray()) outputs.add(c + w);
                }
                break;

            case INSERT_CHARSET:
                for (String w : inputs) {
                        int len = w.length();
                        for (int pos = 0; pos <= len; pos++) {
                            for (char c : op.strArg.toCharArray()) {
                                outputs.add(w.substring(0, pos) + c + w.substring(pos));
                            }
                        }
                }
                break;
            
            case REPLACE:
                for (String w : inputs) {
                    outputs.addAll(generateLeetVariants(w, op.charArg1, op.charArg2));
                }
                break;

            default:
                throw new IllegalStateException("Unknown opcode");
        }
        return outputs;
    }


    /*
    Generates all variants of a word where certain characters are replaced by other certain characters.
    Produces one variant per occurrence of the character to replace.
    */
    static List<String> generateLeetVariants(String word, char from, char to) {
        List<String> variants = new ArrayList<>();
        variants.add(word);

        for (int i = 0; i < word.length(); i++) {
            if (Character.toLowerCase(word.charAt(i)) == Character.toLowerCase(from)) {
                StringBuilder sb = new StringBuilder(word);
                sb.setCharAt(i, to);
                variants.add(sb.toString());
            }
        }

        return variants;
    }


    /*
    Applies a rule (sequence of operations) to a word.
    Deduplicates results while preserving order.
    */
    static List<String> applyRule(String word, Rule rule) {
        List<String> results = new ArrayList<>();
        results.add(word);

        for (Operation op: rule.operations) {
            results = applyOperationToList(results, op);
        }

        return new ArrayList<>(new java.util.LinkedHashSet<>(results));
    }


    /*
    Applies an ordered chain of rules to a base word.
    Deduplicates between stages to control explosion.
    */
    static List<String> applyRuleChain(String word, Rule... rules) {
        List<String> results = new ArrayList<>();
        results.add(word);

        for (Rule rule : rules) {
            List<String> next = new ArrayList<>();
            for (String r : results) {
                next.addAll(applyRule(r, rule));
            }
            results = new ArrayList<>(new java.util.LinkedHashSet<>(next));
        }

        return results;
    }

    /*
    Writes a single user's result line and prints a concise console message.

    Format written to results file:
      username:password_or_<not found>:time_seconds
    */
    private static void writeUserResult(BufferedWriter resultWriter, String username, String foundPassword, double userSeconds) throws Exception {
        if (foundPassword != null) {
            resultWriter.write(username + ":" + foundPassword + ":" + String.format("%.3f", userSeconds));
            resultWriter.newLine();
            System.out.println("Cracked " + username + " in " + String.format("%.3f", userSeconds) + "s: " + foundPassword);
        } else {
            resultWriter.write(username + ":<not found>:" + String.format("%.3f", userSeconds));
            resultWriter.newLine();
            System.out.println("Password not found for user: " + username + " (elapsed " + String.format("%.3f", userSeconds) + "s)");
        }
    }


        /*
        Main cracking driver.

        Description:
            - Entry point for the rule-based password cracking program.
            - Expects two arguments: a Unix-style password file and a dictionary file.

        Flow:
            1. Validate CLI arguments and create output directory `Results`.
            2. Load password entries and dictionary words into memory.
            3. For each user: extend the dictionary with user-specific name variants,
                 apply ordered rule chains to generate candidate variants, hash each
                 candidate using `jcrypt.crypt(salt, candidate)`, and compare against
                 the stored hash.
            4. Record the found password (or `<not found>`) and the per-user elapsed
                 time to the results file in the format `username:password:time_seconds`.
            5. After processing all users, append a summary line and total runtime.

        Output:
            - Writes results to `Results/<input_filename>_results.txt`.
            - Summary line contains the number cracked and total elapsed time.
        */
        public static void main(String[] args) throws Exception {

        if (args.length != 2) {
            System.err.println("Usage: java bf_jcrypt <passwd_file> <dictionary_file>");
            System.exit(1);
        }

        String input_filename = args[0];
        input_filename = input_filename.substring(0, input_filename.length()-4);

        int totalUsers = 0;
        int crackedUsers = 0;

        new java.io.File("Results").mkdirs();

        try (BufferedWriter resultWriter = new BufferedWriter(new FileWriter("Results/" + input_filename + "_results.txt"))) {

            List<UserEntry> users = loadPasswordFile(args[0]);
            List<String> dictionary = loadDictionary(args[1]);

            long totalStart = System.nanoTime();

            for (UserEntry user : users) {
                System.out.println("Cracking user: " + user.username);
                boolean cracked = false;

                totalUsers++;

                List<String> extendedDictionary = addNameDatatoDictionary(user, dictionary);

                long userStart = System.nanoTime();
                String foundPassword = null;

                for (String candidate : extendedDictionary) {

                    for (Rule[] chain : RULE_CHAINS) {

                        List<String> variants = applyRuleChain(candidate, chain);

                        for (String modifiedCandidate : variants) {

                            String hashedCandidate = jcrypt.crypt(user.salt, modifiedCandidate);

                            if (hashedCandidate.equals(user.hash)) {
                                foundPassword = modifiedCandidate;
                                cracked = true;
                                break;
                            }
                        }
                        if (cracked) break;
                    }
                    if (cracked) break;
                }

                double userSeconds = (System.nanoTime() - userStart) / 1e9;

                writeUserResult(resultWriter, user.username, foundPassword, userSeconds);
                if (foundPassword != null) crackedUsers++;
            }

            double totalSeconds = (System.nanoTime() - totalStart) / 1e9;

            System.out.println("Cracked " + crackedUsers + " out of " + totalUsers + " users.");
            resultWriter.write("Cracked " + crackedUsers + " out of " + totalUsers + " users. (" + (100.0 * crackedUsers / totalUsers) + "%)");
            resultWriter.newLine();
            resultWriter.write("Total time: " + String.format("%.3f", totalSeconds) + "s");

        }
    }
}
