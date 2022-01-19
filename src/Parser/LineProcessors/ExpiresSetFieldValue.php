<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use DateTimeImmutable;
use Exception;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiredError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresOldFormatError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresTooLongWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresWrongFormatError;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\SecurityTxt;

class ExpiresSetFieldValue implements LineProcessor
{

	/**
	 * @throws SecurityTxtExpiresOldFormatError
	 * @throws SecurityTxtExpiresWrongFormatError
	 * @throws SecurityTxtExpiredError
	 * @throws SecurityTxtExpiresTooLongWarning
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
					throw new SecurityTxtExpiresOldFormatError($expiresValue);
				} else {
					try {
						$expiresValue = new DateTimeImmutable($value);
					} catch (Exception) {
						$expiresValue = null;
					}
					throw new SecurityTxtExpiresWrongFormatError($expiresValue);
				}
			}
		}
		$expires = new Expires(new DateTimeImmutable($value));
		$securityTxt->setExpires($expires);
	}

}
