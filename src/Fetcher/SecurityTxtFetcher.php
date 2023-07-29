<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use LogicException;
use Spaze\SecurityTxt\Exceptions\SecurityTxtContentTypeError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtContentTypeWrongCharsetError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtSchemeNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtTopLevelDiffersWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtTopLevelPathOnlyWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWellKnownPathOnlyWarning;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotReadUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherNoLocationException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;

class SecurityTxtFetcher
{

	private const MAX_ALLOWED_REDIRECTS = 5;

	/** @var array<string, list<string>> */
	private array $redirects = [];

	private string $finalUrl;

	/** @var list<callable(string): void> */
	private array $onUrl = [];

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
	 * @throws SecurityTxtFetcherNoHttpCodeException
	 * @throws SecurityTxtFetcherNoLocationException
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
	 * @throws SecurityTxtFetcherNoHttpCodeException
	 * @throws SecurityTxtFetcherNoLocationException
	 */
	private function fetchUrl(string $urlTemplate, string $host, bool $noIpv6): SecurityTxtFetcherFetchHostResult
	{
		$url = $this->buildUrl($urlTemplate, $host);
		$this->finalUrl = $url;
		$this->callOnCallback($this->onUrl, $url);
		try {
			$this->redirects[$url] = [];
			$records = @dns_get_record($host, $noIpv6 ? DNS_A : DNS_A | DNS_AAAA); // intentionally @, converted to exception
			if (!$records) {
				throw new SecurityTxtHostNotFoundException($url, $host);
			}
			$records = array_merge(...$records);
			$response = $this->getResponse($this->buildUrl($urlTemplate, $records['ipv6'] ?? $records['ip']), $urlTemplate, $host, true);
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
	 * @throws SecurityTxtFetcherNoHttpCodeException
	 * @throws SecurityTxtFetcherNoLocationException
	 */
	private function getResponse(string $url, string $urlTemplate, string $host, bool $useHostForContextHost): SecurityTxtFetcherResponse
	{
		$response = $this->httpClient->getResponse($url, $useHostForContextHost ? $host : null);
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
			$warnings[] = new SecurityTxtWellKnownPathOnlyWarning();
			$result = $wellKnown;
			$contents = $wellKnownContents;
		} elseif ($wellKnownContents === null && $topLevelContents) {
			$warnings[] = new SecurityTxtTopLevelPathOnlyWarning();
			$result = $topLevel;
			$contents = $topLevelContents;
		} elseif ($wellKnownContents !== $topLevelContents) {
			if ($wellKnownContents === null || $topLevelContents === null) {
				throw new LogicException('This should not happen');
			}
			$warnings[] = new SecurityTxtTopLevelDiffersWarning($wellKnownContents, $topLevelContents);
			$result = $wellKnown;
			$contents = $wellKnownContents;
		} else {
			$result = $wellKnown;
			$contents = $wellKnownContents;
		}
		if ($contents === null) {
			throw new LogicException('This should not happen');
		}

		$contentTypeHeader = $result->getContentTypeHeader();
		$headerParts = $contentTypeHeader ? explode(';', $contentTypeHeader, 2) : [];
		$contentType = isset($headerParts[0]) ? trim($headerParts[0]) : null;
		$charset = isset($headerParts[1]) ? trim($headerParts[1]) : null;
		if (!$contentType || strtolower($contentType) !== 'text/plain') {
			$errors[] = new SecurityTxtContentTypeError($result->getUrl(), $contentType);
		} elseif (!$charset || strtolower($charset) !== 'charset=utf-8') {
			$errors[] = new SecurityTxtContentTypeWrongCharsetError($result->getUrl(), $contentType, $charset);
		}
		$scheme = parse_url($result->getUrl(), PHP_URL_SCHEME);
		if ($scheme !== 'https') {
			$errors[] = new SecurityTxtSchemeNotHttpsError($result->getUrl());
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
	 * @throws SecurityTxtFetcherNoHttpCodeException
	 * @throws SecurityTxtFetcherNoLocationException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtUrlNotFoundException
	 */
	private function redirect(string $url, SecurityTxtFetcherResponse $response, string $urlTemplate, string $host): SecurityTxtFetcherResponse
	{
		$location = $response->getHeader('Location');
		if (!$location) {
			throw new SecurityTxtFetcherNoLocationException($url, $response);
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
