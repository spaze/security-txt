<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Closure;
use LogicException;
use Spaze\SecurityTxt\Exceptions\SecurityTxtTopLevelDiffersWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtTopLevelPathOnlyWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWellKnownPathOnlyWarning;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotReadUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;

class SecurityTxtFetcher
{

	private const MAX_ALLOWED_REDIRECTS = 5;

	/** @var array<string, array<int, string>> */
	private array $redirects = [];


	/**
	 * @param null|Closure(string): void $onFetchUrl
	 * @param null|Closure(string): void $onRedirect
	 * @param null|Closure(string): void $onUrlNotFound
	 */
	public function __construct(
		private ?Closure $onFetchUrl = null,
		private ?Closure $onRedirect = null,
		private ?Closure $onUrlNotFound = null,
	) {
	}


	/**
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtCannotReadUrlException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtHostNotFoundException
	 */
	public function fetchHost(string $host, bool $noIpv6 = false): SecurityTxtFetchResult
	{
		$wellKnown = $this->fetchUrl('https://%s/.well-known/security.txt', $host, $noIpv6);
		$topLevel = $this->fetchUrl('https://%s/security.txt', $host, $noIpv6);
		return $this->getResult($wellKnown, $topLevel);
	}


	/**
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtCannotReadUrlException
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtNotFoundException
	 */
	private function fetchUrl(string $urlTemplate, string $host, bool $noIpv6): SecurityTxtFetcherFetchHostResult
	{
		$url = $this->buildUrl($urlTemplate, $host);
		$this->callOnCallback($this->onFetchUrl, $url);
		try {
			$this->redirects = [];
			$records = @dns_get_record($host, $noIpv6 ? DNS_A : DNS_A | DNS_AAAA);  // intentionally @, converted to exception
			if (!$records) {
				throw new SecurityTxtHostNotFoundException($urlTemplate, $host);
			}
			$contents = $this->getContents($this->buildUrl($urlTemplate, $records[0]['ipv6'] ?? $records[0]['ip']), $urlTemplate, $host, true);
		} catch (SecurityTxtUrlNotFoundException $e) {
			$this->callOnCallback($this->onUrlNotFound, $e->getUrl());
			$contents = null;
		}
		return new SecurityTxtFetcherFetchHostResult(
			$url,
			$contents,
			$e ?? null,
		);
	}


	/**
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtCannotReadUrlException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtUrlNotFoundException
	 */
	private function getContents(string $url, string $urlTemplate, string $host, bool $useHostForContextHost): string
	{
		$options = [
			'http' => [
				'follow_location' => false,
				'ignore_errors' => true,
				'user_agent' => 'spaze/security-txt',
			],
		];
		if ($useHostForContextHost) {
			$options['ssl'] = [
				'peer_name' => $host,
			];
			$options['http']['header'][] = "Host: {$host}";
		}
		$fp = @fopen($url, 'r', context: stream_context_create($options));  // intentionally @, converted to exception
		if (!$fp) {
			throw new SecurityTxtCannotOpenUrlException($url);
		}
		$contents = stream_get_contents($fp);
		if ($contents === false) {
			throw new SecurityTxtCannotReadUrlException($url);
		}
		$metadata = stream_get_meta_data($fp);
		fclose($fp);
		/** @var array{wrapper_data: array<int, string>} $metadata */
		$location = $this->getLocation($url, $metadata['wrapper_data']);
		if ($location) {
			$this->callOnCallback($this->onRedirect, $location);
			$originalUrl = $this->buildUrl($urlTemplate, $host);
			$this->redirects[$originalUrl][] = $location;
			if (count($this->redirects[$originalUrl]) > self::MAX_ALLOWED_REDIRECTS) {
				throw new SecurityTxtTooManyRedirectsException($url, $this->redirects[$originalUrl], self::MAX_ALLOWED_REDIRECTS);
			}
			return $this->getContents($location, $urlTemplate, $host, false);
		}
		return $contents;
	}


	/**
	 * @param string $url
	 * @param array<int, string> $headers
	 * @return string|null
	 * @throws SecurityTxtUrlNotFoundException
	 */
	private function getLocation(string $url, array $headers): ?string
	{
		if (preg_match('~^HTTP/[\d.]+ (\d+)~', $headers[0], $matches)) {
			$code = (int)$matches[1];
			if ($code >= 400) {
				throw new SecurityTxtUrlNotFoundException($url, $code);
			}
			if ($code >= 300) {
				foreach ($headers as $header) {
					if (preg_match('~^Location:\s*(.*)$~i', $header, $matches)) {
						return $matches[1];
					}
				}
			}
		}
		return null;
	}


	/**
	 * @throws SecurityTxtNotFoundException
	 */
	private function getResult(SecurityTxtFetcherFetchHostResult $wellKnown, SecurityTxtFetcherFetchHostResult $topLevel): SecurityTxtFetchResult
	{
		$errors = $warnings = [];
		$wellKnownContents = $wellKnown->getContents();
		$topLevelContents = $topLevel->getContents();
		if ($wellKnownContents === null && $topLevelContents === null) {
			throw new SecurityTxtNotFoundException([
				$wellKnown->getUrl() => $wellKnown->getHttpCode(),
				$topLevel->getUrl() => $topLevel->getHttpCode(),
			]);
		} elseif ($wellKnownContents && $topLevelContents === null) {
			$warnings[] = new SecurityTxtWellKnownPathOnlyWarning();
			$contents = $wellKnownContents;
		} elseif ($wellKnownContents === null && $topLevelContents) {
			$warnings[] = new SecurityTxtTopLevelPathOnlyWarning();
			$contents = $topLevelContents;
		} elseif ($wellKnownContents !== $topLevelContents) {
			if ($wellKnownContents === null || $topLevelContents === null) {
				throw new LogicException('This should not happen');
			}
			$warnings[] = new SecurityTxtTopLevelDiffersWarning($wellKnownContents, $topLevelContents);
			$contents = $wellKnownContents;
		} else {
			$contents = $wellKnownContents;
		}
		if ($contents === null) {
			throw new LogicException('This should not happen');
		}

		return new SecurityTxtFetchResult(
			$wellKnownContents ? $wellKnown->getUrl() : $topLevel->getUrl(),
			$this->redirects,
			$contents,
			$errors,
			$warnings,
		);
	}


	private function callOnCallback(?Closure $onCallback, string ...$params): void
	{
		if ($onCallback) {
			call_user_func_array($onCallback, $params);
		}
	}


	private function buildUrl(string $urlTemplate, string $host): string
	{
		return sprintf($urlTemplate, $host);
	}


	/**
	 * @param Closure(string): void $onFetchUrl
	 */
	public function addOnFetchUrl(Closure $onFetchUrl): void
	{
		$this->onFetchUrl = $onFetchUrl;
	}


	/**
	 * @param Closure(string): void $onRedirect
	 */
	public function addOnRedirect(Closure $onRedirect): void
	{
		$this->onRedirect = $onRedirect;
	}


	/**
	 * @param Closure(string): void $onUrlNotFound
	 */
	public function addOnUrlNotFound(Closure $onUrlNotFound): void
	{
		$this->onUrlNotFound = $onUrlNotFound;
	}

}
