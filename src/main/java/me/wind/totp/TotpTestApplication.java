package me.wind.totp;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TotpTestApplication implements CommandLineRunner {

	private static final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
			1000000000 };
	private Logger logger = LoggerFactory.getLogger(getClass());

	public static void main(String[] args) {
		SpringApplication.run(TotpTestApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {

		Base32 base32 = new Base32(false);
		final SecureRandom r = new SecureRandom();
		final int len = 6;

		byte[] bytes = new byte[20];
		r.nextBytes(bytes);
		String secret = "nus2kfgru73eqycvaqcz7iaarff2dnnx";// base32.encodeAsString(bytes).toLowerCase();
		String url = String.format("otpauth://totp/%s?secret=%s&issuer=%s",
				URLEncoder.encode("测试用户", StandardCharsets.UTF_8), secret,
				URLEncoder.encode("测试网站", StandardCharsets.UTF_8));
		logger.info(url);

		byte[] k = base32.decode(secret.toUpperCase());
		logger.info("k: {}", Arrays.toString(k));
		long time = System.currentTimeMillis() / 1000 / 30;

		byte[] m = ByteBuffer.allocate(8).putLong(time).array();
		logger.info("time: {}, bytes: {}", time, Arrays.toString(m));

		Mac hmac = HmacUtils.getInitializedMac(HmacAlgorithms.HMAC_SHA_1, k);
		hmac.update(m);
		byte[] s = hmac.doFinal();
		logger.info("s: {}", Arrays.toString(s));

		int offset = s[s.length - 1] & 0xf;

		DataInput input = new DataInputStream(new ByteArrayInputStream(s, offset, s.length - offset));
		int value = input.readInt() & 0x7FFFFFFF;
		logger.info("value: {}", value);
		String code = Integer.toString(value % DIGITS_POWER[len]);
		while (code.length() < len) {
			code = '0' + code;
		}
		logger.info(code);
	}
}
