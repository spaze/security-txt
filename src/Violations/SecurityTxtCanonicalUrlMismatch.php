<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

final class SecurityTxtCanonicalUrlMismatch extends SecurityTxtSpecViolation
{

	/**
	 * @param list<string> $canonicalUrls
	 */
	public function __construct(string $fetchedUrl, array $canonicalUrls)
	{
		parent::__construct(
			func_get_args(),
			'The file was fetched from %s but the %s field does not list this URL',
			[$fetchedUrl, 'Canonical'],
			'draft-foudil-securitytxt-09',
			null,
			'Add the URL %s to the %s field, or ensure the file is fetched from one of the listed canonical URLs: %s',
			[$fetchedUrl, 'Canonical', implode(', ', $canonicalUrls)],
			'2.5.2',
		);
	}

}
