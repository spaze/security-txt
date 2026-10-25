<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Spaze\SecurityTxt\Fields\SecurityTxtField;

abstract class SecurityTxtFieldNotUri extends SecurityTxtSpecViolation
{

	/**
	 * @param list<mixed> $constructorParams
	 * @param SecurityTxtField $field
	 * @param string $uri
	 * @param SecurityTxtNotUriReason $reason
	 * @param string|null $correctValue
	 * @param string $since
	 * @param string|null $specSection
	 */
	public function __construct(
		array $constructorParams,
		SecurityTxtField $field,
		string $uri,
		SecurityTxtNotUriReason $reason,
		?string $correctValue,
		string $since,
		?string $specSection,
	) {
		parent::__construct(
			$constructorParams,
			'The %s value (%s) ' . $reason->getFormat(),
			[$field->value, $uri],
			$since,
			self::asUrl($correctValue),
			$reason->getHowToFix(),
			[],
			$specSection,
		);
	}

}
