package org.apache.syncope.core.spring;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.security.Encryptor;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.*;

@RunWith(Enclosed.class)
public class EncryptorTest {

    public static class TestGetInstance {


            @Test
            public void testValidKey() {
                String secretKey = "mySecretKey123";
                boolean expException = false;

                try {
                    Encryptor encryptor = Encryptor.getInstance(secretKey);
                    if (!expException) {
                        assertNotNull("Encryptor instance should not be null for valid keys.", encryptor);
//                        assertTrue("Encryptor instance should be the same for the same key.", encryptor.verify(secretKey, CipherAlgorithm.AES, encryptor.encode(secretKey, CipherAlgorithm.AES)));
                    }
                } catch (IllegalArgumentException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid key: " + e.getMessage());
                    } else {
                        assertTrue("Expected IllegalArgumentException for invalid key.", true);
                    }
                }
            }

            @Test
            public void testInvalidKey() {
                String secretKey = "invalidKey123";
                boolean expException = true;

                try {
                    Encryptor encryptor = Encryptor.getInstance(secretKey);
                    if (expException) {
//                        assertEquals("Encryptor instance should not be the same for different keys.", null, encryptor.decode(secretKey, CipherAlgorithm.AES));
                    }
                } catch (IllegalArgumentException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid key: " + e.getMessage());
                    } else {
                        assertTrue("Expected IllegalArgumentException for invalid key.", true);
                    }
//                } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                         NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                    if(!expException) {
//                        fail("Did not expect an exception for valid key: " + e.getMessage());
//                    } else {
//                        assertTrue("Expected exception for invalid key.", true);
//                    }
                }
            }

            @Test
            public void testEmptyKey() {
                String secretKey = "";
                boolean expException = false;

                try {
                    Encryptor encryptor = Encryptor.getInstance(secretKey);
                    if (expException) {
                        assertNull("Encryptor instance should be null for empty key.", encryptor);
                    }
                } catch (IllegalArgumentException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid key: " + e.getMessage());
                    } else {
                        assertTrue("Expected IllegalArgumentException for empty key.", true);
                    }
                }
            }

            @Test
            public void testNullKey() {
                String secretKey = null;
                boolean expException = false;

                try {
                    Encryptor encryptor = Encryptor.getInstance(secretKey);
                    if (expException) {
                        assertNull("Encryptor instance should be null for null key.", encryptor);
                    }
                } catch (IllegalArgumentException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid key: " + e.getMessage());
                    } else {
                        assertTrue("Expected IllegalArgumentException for null key.", true);
                    }
                }
            }
    }

    public static class TestEncode {

        @Test
        public void testValidKeyAES() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = "mySecretKey123";
            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
            boolean expException = false;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                String encoded = encryptor.encode(value, cipherAlgorithm);
                if (!expException) {
                    assertNotNull("Encoded value should not be null for valid input.", encoded);
                    assertTrue("Encoded value should be verified.", encryptor.verify(value, cipherAlgorithm, encoded));
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if(!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }

        @Test
        public void testValidKeyAES2() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = "mySecretKey123aa";
            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
            boolean expException = false;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                String encoded = encryptor.encode(value, cipherAlgorithm);
                if (!expException) {
                    assertNotNull("Encoded value should not be null for valid input.", encoded);
                    assertTrue("Encoded value should be verified.", encryptor.verify(value, cipherAlgorithm, encoded));
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if(!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }

        @Test
        public void testValidKeyBCRYPT() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = "mySecretKey123aa";
            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.BCRYPT;
            boolean expException = false;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                String encoded = encryptor.encode(value, cipherAlgorithm);
                if (!expException) {
                    assertNotNull("Encoded value should not be null for valid input.", encoded);
                    assertTrue("Encoded value should be verified.", encryptor.verify(value, cipherAlgorithm, encoded));
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if(!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }

        @Test
        public void testValidKeySHA1() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = "mySecretKey123aa";
            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.SHA1;
            boolean expException = false;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                String encoded = encryptor.encode(value, cipherAlgorithm);
                if (!expException) {
                    assertNotNull("Encoded value should not be null for valid input.", encoded);
                    assertTrue("Encoded value should be verified.", encryptor.verify(value, cipherAlgorithm, encoded));
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if(!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }

        @Test
        public void testNullKey() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = null;
            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
            boolean expException = true;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                String encoded = encryptor.encode(value, cipherAlgorithm);
                if (expException) {
                    assertNull("Encoded value should be null for null input.", encoded);
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if(!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }

        public static class TestVerify {

            @Test
            public void testValidKeyAES() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
                String value = "mySecretKey123";
                CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
                boolean setDifferent = false;
                boolean expException = false;

                try {
                    Encryptor encryptor = Encryptor.getInstance("validInstance");
                    boolean verified;
                    if (!setDifferent) {
                        String encoded = encryptor.encode(value, cipherAlgorithm);
                        verified = encryptor.verify(value, cipherAlgorithm, encoded);
                    } else {
                        String encoded = encryptor.encode(value, cipherAlgorithm);
                        verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
                    }

                    if (!expException) {
                        assertTrue("Value should be verified.", verified);
                    } else {
                        assertFalse("Value should not be verified.", verified);
                    }
                } catch (IllegalArgumentException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid input: " + e.getMessage());
                    } else {
                        assertTrue("Expected IllegalArgumentException for invalid input.", true);
                    }
                } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                         NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid input: " + e.getMessage());
                    } else {
                        assertTrue("Expected exception for invalid input.", true);
                    }
                }
            }

            @Test
            public void testValidKeyAES2() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
                String value = "mySecretKey123aa";
                CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
                boolean setDifferent = false;
                boolean expException = false;

                try {
                    Encryptor encryptor = Encryptor.getInstance("validInstance");
                    boolean verified;
                    if (!setDifferent) {
                        String encoded = encryptor.encode(value, cipherAlgorithm);
                        verified = encryptor.verify(value, cipherAlgorithm, encoded);
                    } else {
                        String encoded = encryptor.encode(value, cipherAlgorithm);
                        verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
                    }

                    if (!expException) {
                        assertTrue("Value should be verified.", verified);
                    } else {
                        assertFalse("Value should not be verified.", verified);
                    }
                } catch (IllegalArgumentException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid input: " + e.getMessage());
                    } else {
                        assertTrue("Expected IllegalArgumentException for invalid input.", true);
                    }
                } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                         NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid input: " + e.getMessage());
                    } else {
                        assertTrue("Expected exception for invalid input.", true);
                    }
                }
            }

            @Test
            public void testNullKey() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
                String value = null;
                CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
                boolean setDifferent = false;
                boolean expException = true;

                try {
                    Encryptor encryptor = Encryptor.getInstance("validInstance");
                    boolean verified;
                    if (!setDifferent) {
                        String encoded = encryptor.encode(value, cipherAlgorithm);
                        verified = encryptor.verify(value, cipherAlgorithm, encoded);
                    } else {
                        String encoded = encryptor.encode(value, cipherAlgorithm);
                        verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
                    }

                    if (expException) {
                        assertFalse("Value should not be verified.", verified);
                    }
                } catch (IllegalArgumentException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid input: " + e.getMessage());
                    } else {
                        assertTrue("Expected IllegalArgumentException for invalid input.", true);
                    }
                } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                         NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid input: " + e.getMessage());
                    } else {
                        assertTrue("Expected exception for invalid input.", true);
                    }
                }
            }

            @Test
            public void testDifferentKey() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
                String value = "mySecretKey123";
                CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
                boolean setDifferent = true;
                boolean expException = true;

                try {
                    Encryptor encryptor = Encryptor.getInstance("validInstance");
                    boolean verified;
                    if (!setDifferent) {
                        String encoded = encryptor.encode(value, cipherAlgorithm);
                        verified = encryptor.verify(value, cipherAlgorithm, encoded);
                    } else {
                        String encoded = encryptor.encode(value, cipherAlgorithm);
                        verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
                    }

                    if (expException) {
                        assertFalse("Value should not be verified.", verified);
                    }
                } catch (IllegalArgumentException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid input: " + e.getMessage());
                    } else {
                        assertTrue("Expected IllegalArgumentException for invalid input.", true);
                    }
                } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                         NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                    if (!expException) {
                        fail("Did not expect an exception for valid input: " + e.getMessage());
                    } else {
                        assertTrue("Expected exception for invalid input.", true);
                    }
                }
            }
        }


//        @Test
//        public void testEmptyKey() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
//            String value = "";
//            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
//            boolean expException = false;
//
//            try {
//                Encryptor encryptor = Encryptor.getInstance("validInstance");
//                String encoded = encryptor.encode(value, cipherAlgorithm);
//                if (!expException) {
//                    assertNotNull("Encoded value should not be null for valid input.", encoded);
//                    assertTrue("Encoded value should be verified.", encryptor.verify(value, cipherAlgorithm, encoded));
//                }
//            } catch (IllegalArgumentException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
//                }
//            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                if(!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected exception for invalid input.", true);
//                }
//            }
//        }
    }

    public static class TestVerify {

        @Test
        public void testValidKeyAES() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = "mySecretKey123";
            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
            boolean setDifferent = false;
            boolean expException = false;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                boolean verified;
                if (!setDifferent) {
                    String encoded = encryptor.encode(value, cipherAlgorithm);
                    verified = encryptor.verify(value, cipherAlgorithm, encoded);
                } else {
                    String encoded = encryptor.encode(value, cipherAlgorithm);
                    verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
                }

                if (!expException) {
                    assertTrue("Value should be verified.", verified);
                } else {
                    assertFalse("Value should not be verified.", verified);
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }

//        @Test
//        public void testValidKeyAES2() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
//            String value = "mySecretKey123aa";
//            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
//            boolean setDifferent = false;
//            boolean expException = false;
//
//            try {
//                Encryptor encryptor = Encryptor.getInstance("validInstance");
//                boolean verified;
//                if (!setDifferent) {
//                    String encoded = encryptor.encode(value, cipherAlgorithm);
//                    verified = encryptor.verify(value, cipherAlgorithm, encoded);
//                } else {
//                    String encoded = encryptor.encode(value, cipherAlgorithm);
//                    verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
//                }
//
//                if (!expException) {
//                    assertTrue("Value should be verified.", verified);
//                } else {
//                    assertFalse("Value should not be verified.", verified);
//                }
//            } catch (IllegalArgumentException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
//                }
//            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected exception for invalid input.", true);
//                }
//            }
//        }

        @Test
        public void testNullKey() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = null;
            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
            boolean setDifferent = false;
            boolean expException = true;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                boolean verified;
                if (!setDifferent) {
                    String encoded = encryptor.encode(value, cipherAlgorithm);
                    verified = encryptor.verify(value, cipherAlgorithm, encoded);
                } else {
                    String encoded = encryptor.encode(value, cipherAlgorithm);
                    verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
                }

                if (expException) {
                    assertFalse("Value should not be verified.", verified);
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }

        @Test
        public void testDifferentKey() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = "mySecretKey123";
            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
            boolean setDifferent = true;
            boolean expException = true;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                boolean verified;
                if (!setDifferent) {
                    String encoded = encryptor.encode(value, cipherAlgorithm);
                    verified = encryptor.verify(value, cipherAlgorithm, encoded);
                } else {
                    String encoded = encryptor.encode(value, cipherAlgorithm);
                    verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
                }

                if (expException) {
                    assertFalse("Value should not be verified.", verified);
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }

        //added for badua coverage
        @Test
        public void testNullAlgorithm() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String value = "mySecretKey123";
            CipherAlgorithm cipherAlgorithm = null;
            boolean setDifferent = true;
            boolean expException = true;

            try {
                Encryptor encryptor = Encryptor.getInstance("validInstance");
                boolean verified;
                if (!setDifferent) {
                    String encoded = encryptor.encode(value, cipherAlgorithm);
                    verified = encryptor.verify(value, cipherAlgorithm, encoded);
                } else {
                    String encoded = encryptor.encode(value, cipherAlgorithm);
                    verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
                }

                if (expException) {
                    assertFalse("Value should not be verified.", verified);
                }
            } catch (IllegalArgumentException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
                }
            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
                if (!expException) {
                    fail("Did not expect an exception for valid input: " + e.getMessage());
                } else {
                    assertTrue("Expected exception for invalid input.", true);
                }
            }
        }
    }

//    public static class TestDecode {
//
//        @Test
//        public void testValidKeyAES() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
//            String value = "mySecretKey123";
//            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
//            boolean expException = false;
//
//            try {
//
//                Encryptor encryptor = Encryptor.getInstance("validInstance");
//                String encoded = encryptor.encode(value, cipherAlgorithm);
//
//                String decoded = encryptor.decode(encoded, cipherAlgorithm);
//                if (!expException) {
//                    assertNotNull("Decoded value should not be null for valid input.", decoded);
//                    assertTrue("Decoded value should be verified.", encryptor.verify(decoded, cipherAlgorithm, encoded));
//                }
//            } catch (IllegalArgumentException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
//                }
//            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected exception for invalid input.", true);
//                }
//            }
//        }
//
//        @Test
//        public void testValidKeyAES2() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
//            String value = "mySecretKey123aa";
//            CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;
//            boolean expException = false;
//
//            try {
//                Encryptor encryptor = Encryptor.getInstance("validInstance");
//                String encoded = encryptor.encode(value, cipherAlgorithm);
//                String decoded = encryptor.decode(encoded, cipherAlgorithm);
//                if (!expException) {
//                    assertNotNull("Decoded value should not be null for valid input.", decoded);
//                    assertTrue("Decoded value should be verified.", encryptor.verify(decoded, cipherAlgorithm, encoded));
//                }
//            } catch (IllegalArgumentException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
//                }
//            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected exception for invalid input.", true);
//                }
//            }
//        }
//    }




//
//        private final String secretKey;
//        private final boolean expException;
//
//
//        public TestGetInstance(String secretKey, boolean expException) {
//            this.secretKey = secretKey;
//            this.expException = expException;
//        }
//
//        @Parameterized.Parameters(name = "Test case: secretKey={0}, isValid={1}")
//        public static Collection<Object[]> data() {
//            return Arrays.asList(new Object[][]{
//                    {"mySecretKey123", false},
////                    {"mySecretKey123aa", false},
////                    {"mySecretKey123&&", false},
////                    {"a", false},
////                    {"", false},
////                    {null, true},
////                    {"aVeryLongSecretKey" + "x".repeat(10000), false},
//
//            });
//        }
//
//
//        @Test
//        public void testGetInstance() {
//            try {
//                Encryptor encryptor = Encryptor.getInstance(secretKey);
//                if (!expException) {
//                    assertNotNull("Encryptor instance should not be null for valid keys.", encryptor);
//                    assertTrue("Encryptor instance should be the same for the same key.", encryptor.verify(secretKey, CipherAlgorithm.AES, encryptor.encode(secretKey, CipherAlgorithm.AES)));
//                } else {
//                    assertEquals("Encryptor instance should not be the same for different keys.", encryptor.decode(secretKey, CipherAlgorithm.AES), null);
//                    //assertNull("Encryptor instance should be null for invalid keys.", encryptor);
//                }
//            } catch (IllegalArgumentException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid key: " + e.getMessage());
//                } else {
//                    assertTrue("Expected IllegalArgumentException for invalid key.", true);
//                }
//            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                if(!expException) {
//                    fail("Did not expect an exception for valid key: " + e.getMessage());
//                } else {
//                    assertTrue("Expected exception for invalid key.", true);
//                }
//                //throw new RuntimeException(e);
//            }
//        }


//    @RunWith(Parameterized.class)
//    public static class TestEncode {
//
//        private final String value;
//        private final CipherAlgorithm cipherAlgorithm;
//        private final boolean expException;
//
//        public TestEncode(String value, CipherAlgorithm cipherAlgorithm, boolean expException) {
//            this.value = value;
//            this.cipherAlgorithm = cipherAlgorithm;
//            this.expException = expException;
//        }
//
//        @Parameterized.Parameters()
//        public static Collection<Object[]> data() {
//            return Arrays.asList(new Object[][]{
//                    {"mySecretKey123", CipherAlgorithm.AES, false},
//                    {"mySecretKey123aa", CipherAlgorithm.AES, false},
//                    {"mySecretKey123&&", CipherAlgorithm.AES, false},
//                    {"a", CipherAlgorithm.AES, false},
//                    {"", CipherAlgorithm.AES, false},
//                    {null, CipherAlgorithm.AES, true},
//                    {"aVeryLongSecretKey" + "x".repeat(10000), CipherAlgorithm.AES, false},
//                    {"mySecretKey123", null, false},
//                    //aggiunta per jacoco
//                    //{"mySecretKey123", CipherAlgorithm.BCRYPT, false},
//                    //{"mySecretKey123aa", CipherAlgorithm.SHA1, false},
//
//            });
//        }
//
//        @Test
//        public void testEncode() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
//            try {
//                Encryptor encryptor = Encryptor.getInstance("validInstance");
//                String encoded = encryptor.encode(value, cipherAlgorithm);
//                if (!expException) {
//                    assertNotNull("Encoded value should not be null for valid input.", encoded);
//                    assertTrue("Encoded value should be verified.", encryptor.verify(value, cipherAlgorithm, encoded));
//                } else {
//                    assertNull("Encoded value should be null for invalid input.", encoded);
//                }
//            } catch (IllegalArgumentException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
//                }
//            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected exception for invalid input.", true);
//                }
//                //throw new RuntimeException(e);
//            }
//        }
//    }
//
//    @RunWith(Parameterized.class)
//    public static class TestVerify {
//
//        private final String value;
//        private final CipherAlgorithm cipherAlgorithm;
//        private final boolean expException;
//        private final boolean setDifferent;
//
//        public TestVerify(String value, CipherAlgorithm cipherAlgorithm, boolean setDifferent, boolean expException) {
//            this.value = value;
//            this.cipherAlgorithm = cipherAlgorithm;
//            this.expException = expException;
//            this.setDifferent = setDifferent;
//        }
//
//        @Parameterized.Parameters()
//        public static Collection<Object[]> data() {
//            return Arrays.asList(new Object[][]{
//                    {"mySecretKey123", CipherAlgorithm.AES, false, false},
//                    {"mySecretKey123aa", CipherAlgorithm.AES, false, false},
//                    {"mySecretKey123&&", CipherAlgorithm.AES,  false, false},
//                    {"a", CipherAlgorithm.AES, false, false},
//                    {"", CipherAlgorithm.AES, false, false},
//                    {null, CipherAlgorithm.AES, false, true},
//                    {"aVeryLongSecretKey" + "x".repeat(10000), CipherAlgorithm.AES, false, false},
//                    {"mySecretKey123", CipherAlgorithm.AES, true, true},
//                    {"mySecretKey123aa", CipherAlgorithm.AES, true, true},
//
//                    //aggiunta per jacoco
//                    {"mySecretKey123", CipherAlgorithm.BCRYPT, false, false},
//                    {"mySecretKey123aa", CipherAlgorithm.SHA1, false, false},
//            });
//        }
//        @Test
//        public void testVerify() {
//            try {
//                Encryptor encryptor = Encryptor.getInstance("validInstance");
//                boolean verified;
//                if(!setDifferent) {
//                    String encoded = encryptor.encode(value, cipherAlgorithm);
//                    verified = encryptor.verify(value, cipherAlgorithm, encoded);
//                }else{
//                    String encoded = encryptor.encode(value, cipherAlgorithm);
//                    verified = encryptor.verify(value + "a", cipherAlgorithm, encoded);
//                }
//                if (!expException) {
//                    assertTrue("Value should be verified.", verified);
//                } else {
//                    assertFalse("Value should not be verified.", verified);
//                }
//            } catch (IllegalArgumentException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
//                }
//            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected exception for invalid input.", true);
//                }
//                //throw new RuntimeException(e);
//            }
//        }
//
//    }
//
//    @RunWith(Parameterized.class)
//    public static class TestDecode {
//
//        private final String value;
//        private final CipherAlgorithm cipherAlgorithm;
//        private final boolean expException;
//        private final boolean setDifferent;
//
//        public TestDecode(String value, CipherAlgorithm cipherAlgorithm, boolean setDifferent,  boolean expException) {
//            this.value = value;
//            this.cipherAlgorithm = cipherAlgorithm;
//            this.expException = expException;
//            this.setDifferent = setDifferent;
//        }
//
//        @Parameterized.Parameters()
//        public static Collection<Object[]> data() {
//            return Arrays.asList(new Object[][]{
//                    {"mySecretKey123", CipherAlgorithm.AES, false, false},
//                    {"mySecretKey123aa", CipherAlgorithm.AES, false, false},
//                    {"mySecretKey123&&", CipherAlgorithm.AES, false, false},
//                    {"a", CipherAlgorithm.AES, false, false},
//                    {"", CipherAlgorithm.AES, false, false},
//                    {null, CipherAlgorithm.AES, false, true},
//                    {"aVeryLongSecretKey" + "x".repeat(10000), CipherAlgorithm.AES, false, false},
//                    {"mySecretKey123", CipherAlgorithm.AES, true, true},
//                    {"mySecretKey123aa", CipherAlgorithm.AES, true, true},
//            });
//        }
//
//        @Test
//        public void testDecode() {
//            try {
//                Encryptor encryptor = Encryptor.getInstance("validInstance");
//                String encoded;
//                if (setDifferent) {
//                    encoded = encryptor.encode(value + "a", cipherAlgorithm);
//                }
//                else
//                    encoded = encryptor.encode(value, cipherAlgorithm);
//
//                String decoded = encryptor.decode(encoded, cipherAlgorithm);
//                if (!expException) {
//                    assertNotNull("Decoded value should not be null for valid input.", decoded);
//                    assertEquals("Decoded value should be the same as the original value.", decoded, value);
//                } else {
//                    if(!setDifferent)
//                        assertNull("Decoded value should be null for invalid input.", decoded);
//                    else
//                        assertNotEquals("Decoded value should not be the same as the original value.", decoded, value);
//                }
//            } catch (IllegalArgumentException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected IllegalArgumentException for invalid input.", true);
//                }
//            } catch (UnsupportedEncodingException | NoSuchPaddingException | IllegalBlockSizeException |
//                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
//                if (!expException) {
//                    fail("Did not expect an exception for valid input: " + e.getMessage());
//                } else {
//                    assertTrue("Expected exception for invalid input.", true);
//                }
//                //throw new RuntimeException(e);
//            }
//        }
//
//    }
}
