<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator;

use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalUrlMismatch;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;

final class CanonicalUrlValidator
{

	/**
	 * Validates that the fetched URL is listed in the Canonical field(s)
	 * 
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function validate(SecurityTxt $securityTxt, string $fetchedUrl): array
	{
		$canonicals = $securityTxt->getCanonical();
		
		// If there are no canonical URLs, no validation is needed
		if ($canonicals === []) {
			return [];
		}
		
		// Check if the fetched URL matches any canonical URL
		$canonicalUrls = array_map(fn($canonical) => $canonical->getUri(), $canonicals);
		if (!in_array($fetchedUrl, $canonicalUrls, true)) {
			return [new SecurityTxtCanonicalUrlMismatch($fetchedUrl, $canonicalUrls)];
		}
		
		return [];
	}

}
