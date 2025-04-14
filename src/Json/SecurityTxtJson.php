<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Json;

use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;

final class SecurityTxtJson
{

	/**
	 * @param list<mixed> $violations
	 * @return list<SecurityTxtSpecViolation>
	 * @throws SecurityTxtCannotParseJsonException
	 */
	public function createViolationsFromJsonValues(array $violations): array
	{
		$objects = [];
		foreach ($violations as $violation) {
			if (!is_array($violation) || !isset($violation['class']) || !is_string($violation['class'])) {
				throw new SecurityTxtCannotParseJsonException('class is missing or not a string');
			} elseif (!class_exists($violation['class'])) {
				throw new SecurityTxtCannotParseJsonException("class {$violation['class']} doesn't exist");
			}
			$object = new $violation['class'](...$violation['params']);
			if (!$object instanceof SecurityTxtSpecViolation) {
				throw new SecurityTxtCannotParseJsonException(sprintf("class %s doesn't extend %s", $violation['class'], SecurityTxtSpecViolation::class));
			}
			$objects[] = $object;
		}
		return $objects;
	}


	/**
	 * @param array<array-key, mixed> $values
	 * @return array<string, list<string>>
	 * @throws SecurityTxtCannotParseJsonException
	 */
	public function createRedirectsFromJsonValues(array $values): array
	{
		$redirects = [];
		foreach ($values as $url => $urlRedirects) {
			if (!is_string($url)) {
				throw new SecurityTxtCannotParseJsonException(sprintf('redirects key is a %s not a string', get_debug_type($url)));
			}
			if (!is_array($urlRedirects)) {
				throw new SecurityTxtCannotParseJsonException("redirects > {$url} is not an array");
			}
			foreach ($urlRedirects as $urlRedirect) {
				if (!is_string($urlRedirect)) {
					throw new SecurityTxtCannotParseJsonException('redirects contains an item which is not a string');
				}
				$redirects[$url][] = $urlRedirect;
			}
		}
		return $redirects;
	}

}
