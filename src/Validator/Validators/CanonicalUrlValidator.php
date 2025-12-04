<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Override;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalUrlMismatch;

final class CanonicalUrlValidator implements FieldValidator
{

	#[Override]
	public function validate(SecurityTxt $securityTxt): void
	{
		$fetchedUrl = $securityTxt->getFetchedUrl();
		if ($fetchedUrl === null) {
			return;
		}

		$canonicals = $securityTxt->getCanonical();
		if ($canonicals === []) {
			return;
		}

		$canonicalUrls = array_map(fn($canonical) => $canonical->getUri(), $canonicals);
		if (!in_array($fetchedUrl, $canonicalUrls, true)) {
			throw new SecurityTxtWarning(new SecurityTxtCanonicalUrlMismatch($fetchedUrl, $canonicalUrls));
		}
	}

}
