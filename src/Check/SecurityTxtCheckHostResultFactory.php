<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Json\SecurityTxtJson;
use Spaze\SecurityTxt\Parser\SecurityTxtParseResult;
use Spaze\SecurityTxt\SecurityTxtFactory;

class SecurityTxtCheckHostResultFactory
{

	public function __construct(
		private readonly SecurityTxtFactory $securityTxtFactory,
		private readonly SecurityTxtJson $securityTxtJson,
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
			$parseResult->getLineErrors(),
			$parseResult->getLineWarnings(),
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
	public function createFromJson(string $json): SecurityTxtCheckHostResult
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
		if (!is_array($values['lineErrors'])) {
			throw new SecurityTxtCannotParseJsonException('lineErrors is not an array');
		}
		$lineErrors = [];
		foreach ($values['lineErrors'] as $line => $violations) {
			if (!is_int($line)) {
				throw new SecurityTxtCannotParseJsonException("lineErrors > {$line} key is not an int");
			}
			if (!is_array($violations)) {
				throw new SecurityTxtCannotParseJsonException("lineErrors > {$line} is not an array");
			}
			$lineErrors[$line] = $this->securityTxtJson->createViolationsFromJsonValues(array_values($violations));
		}
		$lineWarnings = [];
		foreach ($values['lineWarnings'] as $line => $violations) {
			if (!is_int($line)) {
				throw new SecurityTxtCannotParseJsonException("lineWarnings > {$line} key is not an int");
			}
			if (!is_array($violations)) {
				throw new SecurityTxtCannotParseJsonException("lineWarnings > {$line} is not an array");
			}
			$lineWarnings[$line] = $this->securityTxtJson->createViolationsFromJsonValues(array_values($violations));
		}
		if (!is_array($values['lineWarnings'])) {
			throw new SecurityTxtCannotParseJsonException('lineWarnings is not an array');
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
			$this->securityTxtJson->createViolationsFromJsonValues(array_values($values['fetchErrors'])),
			$this->securityTxtJson->createViolationsFromJsonValues(array_values($values['fetchWarnings'])),
			$lineErrors,
			$lineWarnings,
			$this->securityTxtJson->createViolationsFromJsonValues(array_values($values['fileErrors'])),
			$this->securityTxtJson->createViolationsFromJsonValues(array_values($values['fileWarnings'])),
			$this->securityTxtFactory->createFromJsonValues($securityTxtFields),
			$values['expiresSoon'],
			$values['expired'],
			$values['expiryDays'],
			$values['valid'],
			$values['strictMode'],
			$values['expiresWarningThreshold'],
		);
	}

}
