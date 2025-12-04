<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalUrlMismatch;

final class CanonicalUrlValidator
{

	public function validate(SecurityTxt $securityTxt, SecurityTxtFetchResult $fetchResult): void
	{
		$canonicals = $securityTxt->getCanonical();
		if ($canonicals === []) {
			return;
		}

		$fetchedUrl = $fetchResult->getFinalUrl();
		$canonicalUrls = array_map(fn($canonical) => $canonical->getUri(), $canonicals);
		if (!in_array($fetchedUrl, $canonicalUrls, true)) {
			throw new SecurityTxtWarning(new SecurityTxtCanonicalUrlMismatch($fetchedUrl, $canonicalUrls));
		}
	}

}
