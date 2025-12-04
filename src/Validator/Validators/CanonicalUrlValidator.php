<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Override;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalUrlMismatch;

final class CanonicalUrlValidator implements FieldValidator
{

	#[Override]
	public function validate(SecurityTxt $securityTxt, ?SecurityTxtFetchResult $fetchResult = null): void
	{
		if ($fetchResult === null) {
			return;
		}

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
