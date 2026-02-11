import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class bf_jcrypt {
    
    /* Data Structures */

    /* class to track user data */
    static class UserEntry {
        String username;
        String salt;
        String hash;
    }
    /* OpCode enum for elementary operators */
    enum OpCode {
        IDENTITY,
        // case ops
        LOWERCASE_ALL,
        CAPITALIZE_FIRST,
        CAPITALIZE_ALL,
        NCAPITALIZE,
        TOGGLE_CASE,
        // structural ops
        REVERSE,
        DUPLICATE,
        REFLECT_FRONT,
        REFLECT_BACK,
        // delete ops
        DELETE_FIRST,
        DELETE_LAST,
        // charset ops
        APPEND_CHARSET,
        PREPEND_CHARSET,
        INSERT_CHARSET,
        // replace
        REPLACE
    }
    /* Operation class to construct each operator */
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

    /* Character sets used by charset operations */
    static final String DIGITS = "0123456789";
    static final String LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    static final String SPECIALS = "!@#$%^&*()-_+=~/`[]{}|:;\"'<>,.?\\\\";
    static final String UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    /* Maximum password length (known constraint) should be 8 but I was missing hits with any length less than 10 */
    static final int MAX_PASS_LEN = 12;

    enum Rule {
        /* Rules for password mutations (Need to update)*/

        IDENTITY(
            new Operation(OpCode.IDENTITY)
        ),
        LOWERCASE_ALL(
            new Operation(OpCode.LOWERCASE_ALL)
        ),
        CAPITALIZE_FIRST(
            new Operation(OpCode.CAPITALIZE_FIRST)
        ),
        CAPITALIZE_ALL(
            new Operation(OpCode.CAPITALIZE_ALL)
        ),
        NCAPITALIZE(
            new Operation(OpCode.NCAPITALIZE)
        ),
        TOGGLE_CASE(
            new Operation(OpCode.TOGGLE_CASE)
        ),
        REVERSE(
            new Operation(OpCode.REVERSE)
        ),
        DUPLICATE(
            new Operation(OpCode.DUPLICATE)
        ),
        REFLECT_FRONT(
            new Operation(OpCode.REFLECT_FRONT)
        ),
        REFLECT_BACK(
            new Operation(OpCode.REFLECT_BACK)
        ),
        DELETE_FIRST(
            new Operation(OpCode.DELETE_FIRST)
        ),

        DELETE_LAST(
            new Operation(OpCode.DELETE_LAST)
        ),
        /* Charset-based rules (create many variants) */
        // append
        APPEND_LOWER(
            new Operation(OpCode.APPEND_CHARSET, LOWERCASE_CHARS)
        ),
        APPEND_UPPER(
            new Operation(OpCode.APPEND_CHARSET, UPPERCASE_CHARS)
        ),
        APPEND_SPECIAL(
            new Operation(OpCode.APPEND_CHARSET, SPECIALS)
        ),
        APPEND_DIGIT(
            new Operation(OpCode.APPEND_CHARSET, DIGITS)
        ),
        // prepend
        PREPEND_LOWER(
            new Operation(OpCode.PREPEND_CHARSET, LOWERCASE_CHARS)
        ),
        PREPEND_UPPER(
            new Operation(OpCode.PREPEND_CHARSET, UPPERCASE_CHARS)
        ),
        PREPEND_SPECIAL(
            new Operation(OpCode.PREPEND_CHARSET, SPECIALS)
        ),
        PREPEND_DIGIT(
            new Operation(OpCode.PREPEND_CHARSET, DIGITS)
        ),
        // insert
        INSERT_LOWER(
            new Operation(OpCode.INSERT_CHARSET, LOWERCASE_CHARS)
        ),
        INSERT_UPPER(
            new Operation(OpCode.INSERT_CHARSET, UPPERCASE_CHARS)
        ),
        INSERT_DIGIT(
            new Operation(OpCode.INSERT_CHARSET, DIGITS)
        ),
        INSERT_SPECIAL(
            new Operation(OpCode.INSERT_CHARSET, SPECIALS)
        ),
        /* Leetspeak / common replacements */
        LEET_A(
            new Operation(OpCode.REPLACE, 'a', '@')
        ),
        LEET_O(
            new Operation(OpCode.REPLACE, 'o', '0')
        ),
        LEET_E(
            new Operation(OpCode.REPLACE, 'e', '3')
        ),
        LEET_S(
            new Operation(OpCode.REPLACE, 's', '$')
        );

        final List<Operation> operations = new ArrayList<>();

        Rule(Operation... ops) {
            for (Operation op : ops) {
                operations.add(op);
            }
        }
    }

    /* List of rule chains to apply multiple rules to the same candidate */
    static final Rule[][] RULE_CHAINS = {

        /* 0. No modification (baseline) */
        { Rule.IDENTITY },

        /* 1. Case normalization (VERY high yield) */
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

        /* 6. Case + leet + digit (very common in assignments) */
        { Rule.CAPITALIZE_FIRST, Rule.LEET_A, Rule.APPEND_DIGIT },
        { Rule.CAPITALIZE_FIRST, Rule.LEET_S, Rule.APPEND_DIGIT },

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


    /* Parsers */
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
                u.salt = u.hash.substring(0, 2);

                users.add(u);
            }
        }
        return users;
    }
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

    /* Rule Engine (where operator logic lives) */
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
                    outputs.add(w); // keep original
                    if (w.indexOf(op.charArg1) >= 0) {
                        outputs.add(w.replace(op.charArg1, op.charArg2));
                    }
                }
                break;

            default:
                throw new IllegalStateException("Unknown opcode");
        }
        // remove any variant that (somehow) exceeds the max length
        outputs.removeIf(s -> s.length() > MAX_PASS_LEN);
        return outputs;
    }
    static List<String> applyRule(String word, Rule rule) {
        // apply the specified rule to the password and return all variants
        List<String> results = new ArrayList<>();
        results.add(word);
        for (Operation op: rule.operations) {
            results = applyOperationToList(results, op);
        }
        // deduplicate while preserving order
        return new ArrayList<>(new java.util.LinkedHashSet<>(results));
    }
    static List<String> applyRuleChain(String word, Rule... rules) {
        List<String> results = new ArrayList<>();
        results.add(word);

        for (Rule rule : rules) {
            List<String> next = new ArrayList<>();
            for (String r : results) {
                next.addAll(applyRule(r, rule));
            }
            // dedupe between stages
            results = new ArrayList<>(new java.util.LinkedHashSet<>(next));
        }

        return results;
    }


    /* Main Cracking Logic */
    public static void main(String[] args) throws Exception {

        if (args.length != 2) {
            System.err.println("Usage: java bf_jcrypt <passwd_file> <dictionary_file>");
            System.err.println("Example: java bf_jcrypt passwd.txt words.txt");
            System.exit(1);
        }

        // open results file for writing
        try (BufferedWriter resultWriter = new BufferedWriter(new FileWriter("results.txt"))) {
            // get password list to crack from args
            List<UserEntry> users = loadPasswordFile(args[0]);
            System.out.println("Loaded " + users.size() + " user entries.");
            // get wordlist path from args
            List<String> dictionary = loadDictionary(args[1]);
            System.out.println("Loaded " + dictionary.size() + " dictionary words.");

            // for each user in the user list
            for (UserEntry user : users) {
                System.out.println("Cracking user: " + user.username);
                boolean cracked = false;

                // for each candidate in the dictionary
                for (String candidate : dictionary) {

                    // for each rule chain in the list of rule chains
                    for (Rule[] chain : RULE_CHAINS) {

                        List<String> variants = applyRuleChain(candidate, chain);

                        /* for each candidate variant produced */
                        for (String modifiedCandidate : variants) {
                            String candidateToHash = modifiedCandidate;
                            if (candidateToHash.length() > MAX_PASS_LEN) {
                                candidateToHash = candidateToHash.substring(0, MAX_PASS_LEN);
                            }
                            String hashedCandidate = jcrypt.crypt(user.salt, candidateToHash);

                            if (hashedCandidate.equals(user.hash)) {
                                System.out.println(
                                    "Cracked: " + user.username + " -> " + modifiedCandidate
                                );

                                resultWriter.write(
                                    user.username + ":" + modifiedCandidate
                                );
                                resultWriter.newLine();

                                cracked = true;
                                break;
                            }
                        }
                        if (cracked) break;
                    }
                    if (cracked) break;
                }
                /* catch unbroken passwords */
                if (!cracked) {
                    System.out.println(
                        "[NOT CRACKED] " + user.username
                    );
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
