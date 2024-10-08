<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use LogicException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotReadUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoLocationHeaderException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtOnlyIpv6HostButIpv6DisabledException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeInvalid;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtSchemeNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelDiffers;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;

class SecurityTxtFetcher
{

	private const MAX_ALLOWED_REDIRECTS = 5;

	/** @var array<string, list<string>> */
	private array $redirects = [];

	private string $finalUrl;

	/** @var list<callable(string): void> */
	private array $onUrl = [];

	/** @var list<callable(string): void> */
	private array $onFinalUrl = [];

	/** @var list<callable(string, string): void> */
	private array $onRedirect = [];

	/** @var list<callable(string): void> */
	private array $onUrlNotFound = [];


	public function __construct(
		private readonly SecurityTxtFetcherHttpClient $httpClient,
	) {
	}


	/**
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtCannotReadUrlException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 * @throws SecurityTxtOnlyIpv6HostButIpv6DisabledException
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
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 * @throws SecurityTxtOnlyIpv6HostButIpv6DisabledException
	 */
	private function fetchUrl(string $urlTemplate, string $host, bool $noIpv6): SecurityTxtFetcherFetchHostResult
	{
		$url = $this->buildUrl($urlTemplate, $host);
		$this->finalUrl = $url;
		$this->callOnCallback($this->onUrl, $url);
		try {
			$this->redirects[$url] = [];
			$records = @dns_get_record($host, DNS_A | DNS_AAAA); // intentionally @, converted to exception
			if (!$records) {
				throw new SecurityTxtHostNotFoundException($url, $host);
			}
			$records = array_merge(...$records);
			if ($noIpv6 && isset($records['ipv6']) && !isset($records['ip'])) {
				throw new SecurityTxtOnlyIpv6HostButIpv6DisabledException($host, $records['ipv6'], $url);
			}
			$ipAddress = !$noIpv6 && isset($records['ipv6']) ? "[{$records['ipv6']}]" : $records['ip'];
			$response = $this->getResponse($this->buildUrl($urlTemplate, $ipAddress), $urlTemplate, $host, true);
		} catch (SecurityTxtUrlNotFoundException $e) {
			$this->callOnCallback($this->onUrlNotFound, $e->getUrl());
			$response = null;
		}
		return new SecurityTxtFetcherFetchHostResult(
			$url,
			$this->finalUrl,
			$response,
			$e ?? null,
		);
	}


	/**
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtCannotReadUrlException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtUrlNotFoundException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 */
	private function getResponse(string $url, string $urlTemplate, string $host, bool $useHostForContextHost): SecurityTxtFetcherResponse
	{
		$builtUrl = $this->buildUrl($urlTemplate, $host);
		$redirects = $this->redirects[$builtUrl] ?? [];
		if ($redirects) {
			array_unshift($redirects, $builtUrl);
		}
		$response = $this->httpClient->getResponse(new SecurityTxtFetcherUrl($url, $redirects), $useHostForContextHost ? $host : null);
		if ($response->getHttpCode() >= 400) {
			throw new SecurityTxtUrlNotFoundException($url, $response->getHttpCode());
		}
		if ($response->getHttpCode() >= 300) {
			return $this->redirect($url, $response, $urlTemplate, $host);
		}
		return $response;
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
			$warnings[] = new SecurityTxtWellKnownPathOnly();
			$result = $wellKnown;
			$contents = $wellKnownContents;
		} elseif ($wellKnownContents === null && $topLevelContents) {
			$warnings[] = new SecurityTxtTopLevelPathOnly();
			$result = $topLevel;
			$contents = $topLevelContents;
		} elseif ($wellKnownContents !== $topLevelContents) {
			if ($wellKnownContents === null || $topLevelContents === null) {
				throw new LogicException('This should not happen');
			}
			$warnings[] = new SecurityTxtTopLevelDiffers($wellKnownContents, $topLevelContents);
			$result = $wellKnown;
			$contents = $wellKnownContents;
		} else {
			$result = $wellKnown;
			$contents = $wellKnownContents;
		}
		if ($contents === null) {
			throw new LogicException('This should not happen');
		}
		$this->callOnCallback($this->onFinalUrl, $result->getFinalUrl());

		$contentTypeHeader = $result->getContentTypeHeader();
		$headerParts = $contentTypeHeader ? explode(';', $contentTypeHeader, 2) : [];
		$contentType = isset($headerParts[0]) ? trim($headerParts[0]) : null;
		$charset = isset($headerParts[1]) ? trim($headerParts[1]) : null;
		if (!$contentType || strtolower($contentType) !== 'text/plain') {
			$errors[] = new SecurityTxtContentTypeInvalid($result->getUrl(), $contentType);
		} elseif (!$charset || strtolower($charset) !== 'charset=utf-8') {
			$errors[] = new SecurityTxtContentTypeWrongCharset($result->getUrl(), $contentType, $charset);
		}
		$scheme = parse_url($result->getUrl(), PHP_URL_SCHEME);
		if ($scheme !== 'https') {
			$errors[] = new SecurityTxtSchemeNotHttps($result->getUrl());
		}
		return new SecurityTxtFetchResult(
			$result->getUrl(),
			$result->getFinalUrl(),
			$this->redirects,
			$contents,
			$errors,
			$warnings,
		);
	}


	/**
	 * @param list<callable> $onCallbacks
	 */
	private function callOnCallback(array $onCallbacks, string ...$params): void
	{
		foreach ($onCallbacks as $onCallback) {
			$onCallback(...$params);
		}
	}


	private function buildUrl(string $urlTemplate, string $host): string
	{
		return sprintf($urlTemplate, $host);
	}


	/**
	 * @param callable(string): void $onUrl
	 */
	public function addOnUrl(callable $onUrl): void
	{
		$this->onUrl[] = $onUrl;
	}


	/**
	 * @param callable(string): void $onFinalUrl
	 */
	public function addOnFinalUrl(callable $onFinalUrl): void
	{
		$this->onFinalUrl[] = $onFinalUrl;
	}


	/**
	 * @param callable(string, string): void $onRedirect
	 */
	public function addOnRedirect(callable $onRedirect): void
	{
		$this->onRedirect[] = $onRedirect;
	}


	/**
	 * @param callable(string): void $onUrlNotFound
	 */
	public function addOnUrlNotFound(callable $onUrlNotFound): void
	{
		$this->onUrlNotFound[] = $onUrlNotFound;
	}


	/**
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtCannotReadUrlException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtUrlNotFoundException
	 */
	private function redirect(string $url, SecurityTxtFetcherResponse $response, string $urlTemplate, string $host): SecurityTxtFetcherResponse
	{
		$location = $response->getHeader('Location');
		if (!$location) {
			throw new SecurityTxtNoLocationHeaderException($url, $response);
		} else {
			$originalUrl = $this->buildUrl($urlTemplate, $host);
			$previousUrl = $this->redirects[$originalUrl][array_key_last($this->redirects[$originalUrl])] ?? $originalUrl;
			$this->callOnCallback($this->onRedirect, $previousUrl, $location);
			$this->redirects[$originalUrl][] = $location;
			$this->finalUrl = $location;
			if (count($this->redirects[$originalUrl]) > self::MAX_ALLOWED_REDIRECTS) {
				throw new SecurityTxtTooManyRedirectsException($url, $this->redirects[$originalUrl], self::MAX_ALLOWED_REDIRECTS);
			}
			return $this->getResponse($location, $urlTemplate, $host, false);
		}
	}

}
