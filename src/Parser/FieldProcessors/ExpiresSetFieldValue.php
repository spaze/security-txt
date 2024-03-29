<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use DateTimeImmutable;
use Exception;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresOldFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresWrongFormat;

class ExpiresSetFieldValue implements FieldProcessor
{

	/**
	 * @throws SecurityTxtError
	 * @throws SecurityTxtWarning
	 * @throws Exception
	 */
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$expiresValue = DateTimeImmutable::createFromFormat(DATE_RFC3339, $value);
		if (!$expiresValue) {
			$expiresValue = DateTimeImmutable::createFromFormat(DATE_RFC3339_EXTENDED, $value);
			if (!$expiresValue) {
				$expiresValue = DateTimeImmutable::createFromFormat(DATE_RFC2822, $value);
				if ($expiresValue) {
					throw new SecurityTxtError(new SecurityTxtExpiresOldFormat($expiresValue));
				} else {
					try {
						$expiresValue = new DateTimeImmutable($value);
					} catch (Exception) {
						$expiresValue = null;
					}
					throw new SecurityTxtError(new SecurityTxtExpiresWrongFormat($expiresValue));
				}
			}
		}
		$expires = new Expires(new DateTimeImmutable($value));
		$securityTxt->setExpires($expires);
	}

}
