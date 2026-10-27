package org.egov.hrms.utils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.egov.hrms.web.contract.EmployeeSearchCriteria;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

@Service
public class HRMSUtils {

	private static final String UPPER_CASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static final String LOWER_CASE = "abcdefghijklmnopqrstuvwxyz";
	private static final String DIGITS = "0123456789";

	private final SecureRandom random = new SecureRandom();
	
	@Value("${egov.hrms.default.pwd.length}")
	private Integer pwdLength;

	@Value("${egov.pwd.allowed.special.characters}")
	private String allowedPasswordSpecialCharacters;
	
	/**
	 * Generates a random password that always satisfies egov-user's password
	 * policy: at least one upper-case letter, one lower-case letter, one digit
	 * and one of the allowed special characters, with no whitespace.
	 *
	 * One character is drawn from each required class, the rest are drawn from
	 * the union of all classes, and the result is shuffled. All draws use
	 * {@link SecureRandom}. The length is {@code egov.hrms.default.pwd.length}
	 * (never fewer than the number of required classes).
	 *
	 * The password is deliberately NOT derived from the employee's details:
	 * {@code params} is accepted only for caller compatibility and is ignored.
	 *
	 * @param params ignored
	 * @return the generated password
	 */
	public String generatePassword(List<String> params) {
		String[] requiredClasses = { UPPER_CASE, LOWER_CASE, DIGITS, allowedPasswordSpecialCharacters };
		String allChars = String.join("", requiredClasses);
		int length = Math.max(pwdLength, requiredClasses.length);

		List<Character> chars = new ArrayList<>(length);
		for (String charClass : requiredClasses)
			chars.add(randomChar(charClass));
		while (chars.size() < length)
			chars.add(randomChar(allChars));
		Collections.shuffle(chars, random);

		StringBuilder password = new StringBuilder(length);
		chars.forEach(password::append);
		return password.toString();
	}

	private char randomChar(String chars) {
		return chars.charAt(random.nextInt(chars.length()));
	}

	public boolean isAssignmentSearchReqd(EmployeeSearchCriteria criteria) {
		return (! CollectionUtils.isEmpty(criteria.getPositions()) || null != criteria.getAsOnDate()
				|| !CollectionUtils.isEmpty(criteria.getDepartments()) || !CollectionUtils.isEmpty(criteria.getDesignations()));
	}
}
