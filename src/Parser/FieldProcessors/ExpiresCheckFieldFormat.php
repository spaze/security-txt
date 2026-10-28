<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use DateMalformedStringException;
use DateTimeImmutable;
use Override;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresOldFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresWrongFormat;

final readonly class ExpiresCheckFieldFormat implements FieldProcessor
{

	/**
	 * RFC 3339 section 5.6, the `T` and the `Z` in either case, and any number of digits in a fraction of a second
	 */
	private const string DATE_TIME = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d++)?(?:Z|[+-]\d{2}:\d{2})$/iD';


	/**
	 * @throws SecurityTxtError
	 */
	#[Override]
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		if (preg_match(self::DATE_TIME, $value) === 1) {
			return;
		}
		$expiresValue = DateTimeImmutable::createFromFormat(DATE_RFC2822, $value);
		if ($expiresValue !== false) {
			throw new SecurityTxtError(new SecurityTxtExpiresOldFormat($expiresValue->format(SecurityTxtExpires::FORMAT)));
		}
		try {
			$expiresValue = new DateTimeImmutable($value);
		} catch (DateMalformedStringException) {
			$expiresValue = null;
		}
		throw new SecurityTxtError(new SecurityTxtExpiresWrongFormat($expiresValue?->format(SecurityTxtExpires::FORMAT)));
	}

}
