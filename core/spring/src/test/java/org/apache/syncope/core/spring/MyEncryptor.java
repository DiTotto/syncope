package org.apache.syncope.core.spring;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.security.Encryptor;
import org.apache.syncope.core.spring.security.SecureRandomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MyEncryptor {

    private static final Logger LOG = LoggerFactory.getLogger(Encryptor.class);
    private SecretKeySpec keySpec;

    private static final Map<String, Encryptor> INSTANCES = new ConcurrentHashMap<>();
    private static final String DEFAULT_SECRET_KEY = "1abcdefghilmnopqrstuvz2!";

    public static MyEncryptor getInstance(final String secretKey) {
        String actualKey = StringUtils.isBlank(secretKey) ? DEFAULT_SECRET_KEY : secretKey;

        MyEncryptor instance;
        instance = new MyEncryptor(actualKey);


        return instance;
    }

    private MyEncryptor(final String secretKey) {


        try {
            keySpec = new SecretKeySpec(ArrayUtils.subarray(
                    secretKey.getBytes(StandardCharsets.UTF_8), 0, 16),
                    CipherAlgorithm.AES.getAlgorithm());
        } catch (Exception e) {
            LOG.error("Error during key specification", e);
        }

    }
}
