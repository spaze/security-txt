<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Parser\SecurityTxtParseResult;
use Spaze\SecurityTxt\SecurityTxtFactory;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;

class SecurityTxtCheckHostResultFactory
{

	public function __construct(
		private readonly SecurityTxtFactory $securityTxtFactory,
	) {
	}


	public function create(string $host, SecurityTxtParseResult $parseResult): SecurityTxtCheckHostResult
	{
		return new SecurityTxtCheckHostResult(
			$host,
			$parseResult->getFetchResult()?->getRedirects() ?? [],
			$parseResult->getFetchResult()?->getConstructedUrl(),
			$parseResult->getFetchResult()?->getFinalUrl(),
			$parseResult->getFetchResult()?->getContents(),
			$parseResult->getFetchErrors(),
			$parseResult->getFetchWarnings(),
			$parseResult->getParseErrors(),
			$parseResult->getParseWarnings(),
			$parseResult->getFileErrors(),
			$parseResult->getFileWarnings(),
			$parseResult->getSecurityTxt(),
			$parseResult->isExpiresSoon(),
			$parseResult->getSecurityTxt()->getExpires()?->isExpired(),
			$parseResult->getSecurityTxt()->getExpires()?->inDays(),
			$parseResult->isValid(),
			$parseResult->isStrictMode(),
			$parseResult->getExpiresWarningThreshold(),
		);
	}


	/**
	 * @throws SecurityTxtCannotParseJsonException
	 */
	public function createFromSimplifiedJson(string $json): SecurityTxtCheckHostResult
	{
		$values = json_decode($json, true);
		if (!is_array($values)) {
			throw new SecurityTxtCannotParseJsonException('not an array');
		}
		if (!is_string($values['host'])) {
			throw new SecurityTxtCannotParseJsonException('host is not a string');
		}
		if ($values['redirects'] !== null) {
			if (!is_array($values['redirects'])) {
				throw new SecurityTxtCannotParseJsonException('redirects is not an array');
			}
			$redirects = [];
			foreach ($values['redirects'] as $url => $urlRedirects) {
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
		}
		if ($values['constructedUrl'] !== null && !is_string($values['constructedUrl'])) {
			throw new SecurityTxtCannotParseJsonException('constructedUrl is not a string');
		}
		if ($values['finalUrl'] !== null && !is_string($values['finalUrl'])) {
			throw new SecurityTxtCannotParseJsonException('finalUrl is not a string');
		}
		if ($values['contents'] !== null && !is_string($values['contents'])) {
			throw new SecurityTxtCannotParseJsonException('contents is not a string');
		}
		if (!is_array($values['fetchErrors'])) {
			throw new SecurityTxtCannotParseJsonException('fetchErrors is not an array');
		}
		if (!is_array($values['fetchWarnings'])) {
			throw new SecurityTxtCannotParseJsonException('fetchWarnings is not an array');
		}
		if (!is_array($values['parseErrors'])) {
			throw new SecurityTxtCannotParseJsonException('parseErrors is not an array');
		}
		$parseErrors = [];
		foreach ($values['parseErrors'] as $line => $violations) {
			if (!is_int($line)) {
				throw new SecurityTxtCannotParseJsonException("parseErrors > {$line} key is not an int");
			}
			if (!is_array($violations)) {
				throw new SecurityTxtCannotParseJsonException("parseErrors > {$line} is not an array");
			}
			$parseErrors[$line] = $this->createViolations(array_values($violations));
		}
		$parseWarnings = [];
		foreach ($values['parseWarnings'] as $line => $violations) {
			if (!is_int($line)) {
				throw new SecurityTxtCannotParseJsonException("parseWarnings > {$line} key is not an int");
			}
			if (!is_array($violations)) {
				throw new SecurityTxtCannotParseJsonException("parseWarnings > {$line} is not an array");
			}
			$parseWarnings[$line] = $this->createViolations(array_values($violations));
		}
		if (!is_array($values['parseWarnings'])) {
			throw new SecurityTxtCannotParseJsonException('parseWarnings is not an array');
		}
		if (!is_array($values['fileErrors'])) {
			throw new SecurityTxtCannotParseJsonException('fileErrors is not an array');
		}
		if (!is_array($values['fileWarnings'])) {
			throw new SecurityTxtCannotParseJsonException('fileWarnings is not an array');
		}
		if (!is_array($values['securityTxt'])) {
			throw new SecurityTxtCannotParseJsonException('securityTxt is not an array');
		}
		$securityTxtFields = [];
		foreach ($values['securityTxt'] as $field => $fieldValues) {
			if (!is_string($field)) {
				throw new SecurityTxtCannotParseJsonException("securityTxt > {$field} key is not a string");
			}
			if ($fieldValues !== null && !is_array($fieldValues)) {
				throw new SecurityTxtCannotParseJsonException("securityTxt > {$field} is not an array");
			}
			$securityTxtFields[$field] = $fieldValues;
		}
		return new SecurityTxtCheckHostResult(
			$values['host'],
			$redirects ?? null,
			$values['constructedUrl'],
			$values['finalUrl'],
			$values['contents'],
			$this->createViolations(array_values($values['fetchErrors'])),
			$this->createViolations(array_values($values['fetchWarnings'])),
			$parseErrors,
			$parseWarnings,
			$this->createViolations(array_values($values['fileErrors'])),
			$this->createViolations(array_values($values['fileWarnings'])),
			$this->securityTxtFactory->createFromJsonValues($securityTxtFields),
			$values['expiresSoon'],
			$values['expired'],
			$values['expiryDays'],
			$values['valid'],
			$values['strictMode'],
			$values['expiresWarningThreshold'],
		);
	}


	/**
	 * @param list<mixed> $violations
	 * @return list<SecurityTxtSpecViolation>
	 * @throws SecurityTxtCannotParseJsonException
	 */
	private function createViolations(array $violations): array
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

}
