<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Json\SecurityTxtJson;

class SecurityTxtFetchResultFactory
{

	public function __construct(
		private readonly SecurityTxtJson $securityTxtJson,
	) {
	}


	/**
	 * @throws SecurityTxtCannotParseJsonException
	 */
	public function createFromJson(string $json): SecurityTxtFetchResult
	{
		$values = json_decode($json, true);
		if (!is_array($values)) {
			throw new SecurityTxtCannotParseJsonException('not an array');
		}
		if (!is_string($values['constructedUrl'])) {
			throw new SecurityTxtCannotParseJsonException('constructedUrl is not a string');
		}
		if (!is_string($values['finalUrl'])) {
			throw new SecurityTxtCannotParseJsonException('finalUrl is not a string');
		}
		if (!is_array($values['redirects'])) {
			throw new SecurityTxtCannotParseJsonException('redirects is not an array');
		}
		$redirects = $this->securityTxtJson->createRedirectsFromJsonValues($values['redirects']);
		if (!is_string($values['contents'])) {
			throw new SecurityTxtCannotParseJsonException('contents is not a string');
		}
		if (!is_array($values['errors'])) {
			throw new SecurityTxtCannotParseJsonException('errors is not an array');
		}
		if (!is_array($values['warnings'])) {
			throw new SecurityTxtCannotParseJsonException('warnings is not an array');
		}
		return new SecurityTxtFetchResult(
			$values['constructedUrl'],
			$values['finalUrl'],
			$redirects,
			$values['contents'],
			$this->securityTxtJson->createViolationsFromJsonValues(array_values($values['errors'])),
			$this->securityTxtJson->createViolationsFromJsonValues(array_values($values['warnings'])),
		);
	}

}
