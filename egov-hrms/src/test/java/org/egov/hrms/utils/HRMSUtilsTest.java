package org.egov.hrms.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class HRMSUtilsTest {

	/*
	 * egov-user's password policy (core-services/egov-user application.properties
	 * and UserService.validatePassword): egov.user.pwd.pattern checked with
	 * Matcher.find(), plus egov.user.pwd.pattern.min.length /
	 * egov.user.pwd.pattern.max.length.
	 */
	private static final Pattern EGOV_USER_PWD_PATTERN =
			Pattern.compile("((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%])(?=\\S+$).*$)");
	private static final int EGOV_USER_PWD_MIN_LENGTH = 8;
	private static final int EGOV_USER_PWD_MAX_LENGTH = 15;

	private static final int ITERATIONS = 100_000;

	/**
	 * Inputs shaped like EmployeeService.enrichUser builds them: code, mobile,
	 * tenantId and the upper-cased name. Two-word and space-heavy names are what
	 * used to produce a password with no upper-case letter.
	 */
	private static final List<List<String>> INPUTS = Arrays.asList(
			Arrays.asList("EMP-BOMET-000016", "0712345678", "ke.bomet", "JANE WANJIKU"),
			Arrays.asList("EMP-KE-000001", "0700000000", "ke", "A B"),
			Arrays.asList("EMP-001", "0799999999", "ke.nairobi", "MARY  ANN   O.  DOE"),
			Arrays.asList("123", "0711111111", "pg.citya", "X Y Z"));

	private HRMSUtils hrmsUtils;

	@BeforeEach
	void setUp() {
		hrmsUtils = new HRMSUtils();
		// Defaults from egov-hrms application.properties.
		ReflectionTestUtils.setField(hrmsUtils, "pwdLength", 8);
		ReflectionTestUtils.setField(hrmsUtils, "allowedPasswordSpecialCharacters", "@#$%");
	}

	@Test
	void generatedPasswordsAlwaysSatisfyEgovUserPolicy() {
		int failures = 0;
		List<String> samples = new ArrayList<>();
		for (int i = 0; i < ITERATIONS; i++) {
			List<String> input = INPUTS.get(i % INPUTS.size());
			String password = hrmsUtils.generatePassword(new ArrayList<>(input));
			if (!satisfiesEgovUserPolicy(password)) {
				failures++;
				if (samples.size() < 10)
					samples.add(input + " -> '" + password + "'");
			}
		}
		assertEquals(0, failures, failures + "/" + ITERATIONS
				+ " passwords rejected by egov-user's policy, e.g. " + samples);
	}

	@Test
	void generatedPasswordHasConfiguredLength() {
		assertEquals(8, hrmsUtils.generatePassword(new ArrayList<>(INPUTS.get(0))).length());

		ReflectionTestUtils.setField(hrmsUtils, "pwdLength", 15);
		assertEquals(15, hrmsUtils.generatePassword(new ArrayList<>(INPUTS.get(0))).length());
	}

	private static boolean satisfiesEgovUserPolicy(String password) {
		return password.length() >= EGOV_USER_PWD_MIN_LENGTH
				&& password.length() <= EGOV_USER_PWD_MAX_LENGTH
				&& EGOV_USER_PWD_PATTERN.matcher(password).find()
				// Stricter than find(): every character, not just a suffix, is non-blank.
				&& password.chars().noneMatch(Character::isWhitespace);
	}
}
