<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType;
use Throwable;

final class SecurityTxtNotFoundException extends SecurityTxtFetcherException
{

	/** @var array<string, array{0:value-of<SecurityTxtIpAddressType>, 1:int}> IP address => DNS type, HTTP code */
	private array $ipAddresses = [];

	/** @var array<string, list<string>> original URL => redirects */
	private array $allRedirects = [];


	/**
	 * @param non-empty-array<string, array{ip:string, type:value-of<SecurityTxtIpAddressType>, code:int, redirects:list<string>, html:bool, truncated:bool}> $urls URL => IP address, IP address type, HTTP code, redirects, regular HTML page?, response too long?
	 */
	public function __construct(array $urls, string $wellKnownUrl, ?Throwable $previous = null)
	{
		$message = "Can't read %s: ";
		$messageValues = ['security.txt'];
		foreach ($urls as $url => $components) {
			if ($this->ipAddresses !== []) {
				$message .= ', '; // Not added in the first iteration
			}
			if ($components['truncated'] && $components['html']) {
				$message .= '%s (%s) => regular HTML page and too long';
			} elseif ($components['truncated']) {
				$message .= '%s (%s) => response too long';
			} elseif ($components['html']) {
				$message .= '%s (%s) => regular HTML page';
			} else {
				$message .= '%s (%s) => %s';
			}
			$messageValues[] = $url;
			$messageValues[] = $components['ip'];
			if (!$components['html'] && !$components['truncated']) {
				$messageValues[] = (string)$components['code'];
			}
			$this->ipAddresses[$components['ip']] = [$components['type'], $components['code']];
			if ($components['redirects'] !== []) {
				$this->allRedirects[$url] = $components['redirects'];
				$message .= $components['html'] || $components['truncated'] ? ' (final page after redirects)' : ' (final code after redirects)';
			}
		}
		parent::__construct([$urls, $wellKnownUrl], $message, $messageValues, $wellKnownUrl, previous: $previous);
	}


	/**
	 * @return array<string, array{0:value-of<SecurityTxtIpAddressType>, 1:int}> IP address => DNS type, HTTP code
	 */
	public function getIpAddresses(): array
	{
		return $this->ipAddresses;
	}


	/**
	 * @return array<string, list<string>> original URL => redirects
	 */
	public function getAllRedirects(): array
	{
		return $this->allRedirects;
	}

}
