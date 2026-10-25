<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

final class SecurityTxtFileLocationNotUri extends SecurityTxtSpecViolation
{

	public function __construct(string $uri, SecurityTxtNotUriReason $reason = SecurityTxtNotUriReason::Unspecified, ?string $correctValue = null)
	{
		parent::__construct(
			func_get_args(),
			'The location of the file %s ' . $reason->getFormat(),
			[$uri],
			'draft-foudil-securitytxt-00',
			self::asUrl($correctValue),
			$reason->getHowToFix(),
			[],
			'3',
		);
	}

}
