<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use LogicException;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsProvider;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtConnectedToWrongIpAddressException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidTypeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotPublicException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoLocationHeaderException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtOnlyIpv6HostButIpv6DisabledException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNoSchemeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlUnsupportedSchemeException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\SecurityTxtContentType;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeInvalid;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelDiffers;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;

final class SecurityTxtFetcher
{

	/** @var array<string, list<string>> */
	private array $redirects = [];

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
		private readonly SecurityTxtUrlParser $urlParser,
		private readonly SecurityTxtSplitLines $splitLines,
		private readonly SecurityTxtDnsProvider $dnsLookupProvider,
		private readonly int $maxAllowedRedirects = 5,
	) {
		if ($this->maxAllowedRedirects < 0) {
			throw new LogicException('maxAllowedRedirects must be greater than or equal to 0 (0 means no redirects allowed)');
		}
	}


	/**
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtHostIpAddressNotPublicException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 * @throws SecurityTxtOnlyIpv6HostButIpv6DisabledException
	 * @throws SecurityTxtHostIpAddressInvalidTypeException
	 * @throws SecurityTxtHostIpAddressNotFoundException
	 * @throws SecurityTxtUrlNoSchemeException
	 * @throws SecurityTxtUrlUnsupportedSchemeException
	 * @throws SecurityTxtCannotParseHostnameException
	 * @throws SecurityTxtConnectedToWrongIpAddressException
	 * @throws SecurityTxtHostIpAddressInvalidException
	 */
	public function fetchHost(string $host, bool $requireTopLevelLocation = false, bool $noIpv6 = false): SecurityTxtFetchResult
	{
		$wellKnown = $this->fetchUrl(sprintf('https://%s/.well-known/security.txt', $host), $host, $noIpv6);
		$topLevel = $this->fetchUrl(sprintf('https://%s/security.txt', $host), $host, $noIpv6);
		return $this->getResult($wellKnown, $topLevel, $requireTopLevelLocation);
	}


	/**
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtHostIpAddressNotPublicException
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 * @throws SecurityTxtOnlyIpv6HostButIpv6DisabledException
	 * @throws SecurityTxtHostIpAddressInvalidTypeException
	 * @throws SecurityTxtHostIpAddressNotFoundException
	 * @throws SecurityTxtUrlNoSchemeException
	 * @throws SecurityTxtUrlUnsupportedSchemeException
	 * @throws SecurityTxtCannotParseHostnameException
	 * @throws SecurityTxtConnectedToWrongIpAddressException
	 * @throws SecurityTxtHostIpAddressInvalidException
	 */
	private function fetchUrl(string $url, string $host, bool $noIpv6): SecurityTxtFetcherFetchHostResult
	{
		$finalUrl = $url;
		$this->callOnCallback($this->onUrl, $url);
		try {
			$response = $this->getResponse(new SecurityTxtFetcherUrl($url, $this->getRedirects($url)), $host, $url, $finalUrl, $noIpv6);
			$ipAddress = $response->getIpAddress();
			$ipAddressType = $response->getIpAddressType();
		} catch (SecurityTxtUrlNotFoundException $e) {
			$this->callOnCallback($this->onUrlNotFound, $e->getUrl());
			$response = null;
			$ipAddress = $e->getIpAddress();
			$ipAddressType = $e->getIpAddressType();
		}
		return new SecurityTxtFetcherFetchHostResult(
			$url,
			$finalUrl,
			$ipAddress,
			$ipAddressType,
			isset($e) ? $e->getCode() : 200,
			$response,
		);
	}


	/**
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtUrlNotFoundException
	 * @throws SecurityTxtHostIpAddressInvalidTypeException
	 * @throws SecurityTxtHostIpAddressNotFoundException
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtOnlyIpv6HostButIpv6DisabledException
	 * @throws SecurityTxtHostIpAddressNotPublicException
	 * @throws SecurityTxtCannotParseHostnameException
	 * @throws SecurityTxtHostIpAddressInvalidException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 * @throws SecurityTxtUrlNoSchemeException
	 * @throws SecurityTxtUrlUnsupportedSchemeException
	 * @throws SecurityTxtConnectedToWrongIpAddressException
	 */
	private function getResponse(SecurityTxtFetcherUrl $url, string $host, string $originalUrl, string &$finalUrl, bool $noIpv6): SecurityTxtFetcherResponse
	{
		$dnsRecords = $this->dnsLookupProvider->getRecords($url->getUrl(), $host);
		$ipRecord = $dnsRecords->getIpRecord();
		$ipv6Record = $dnsRecords->getIpv6Record();
		if ($noIpv6 && $ipv6Record !== null && $ipRecord === null) {
			throw new SecurityTxtOnlyIpv6HostButIpv6DisabledException($host, $ipv6Record, $url->getUrl());
		}
		if (!$noIpv6 && $ipv6Record !== null) {
			$ipAddress = $ipv6Record;
			$ipAddressType = DNS_AAAA;
		} elseif ($ipRecord !== null) {
			$ipAddress = $ipRecord;
			$ipAddressType = DNS_A;
		}
		if (!isset($ipAddress) || !isset($ipAddressType)) {
			throw new SecurityTxtHostIpAddressNotFoundException($url->getUrl(), $host);
		}
		$this->validateIpAddress($ipAddress, $ipAddressType, $host, $url);

		$response = $this->httpClient->getResponse($url, $host, $ipAddress, $ipAddressType);
		if ($response->getHttpCode() >= 400) {
			throw new SecurityTxtUrlNotFoundException($url->getUrl(), $response->getHttpCode(), $ipAddress, $ipAddressType);
		}
		if ($response->getHttpCode() >= 300) {
			return $this->redirect($url->getUrl(), $originalUrl, $response, $finalUrl, $noIpv6);
		}
		return $response;
	}


	/**
	 * @phpstan-param DNS_A|DNS_AAAA $type
	 * @psalm-param int $type
	 * @throws SecurityTxtHostIpAddressInvalidException
	 * @throws SecurityTxtHostIpAddressNotPublicException
	 */
	private function validateIpAddress(string $ipAddress, int $type, string $host, SecurityTxtFetcherUrl $url): void
	{
		$flag = $type === DNS_A ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;
		if (filter_var($ipAddress, FILTER_VALIDATE_IP, $flag) === false) {
			throw new SecurityTxtHostIpAddressInvalidException($host, $ipAddress, $type, $url->getUrl());
		}
		if (filter_var($ipAddress, FILTER_VALIDATE_IP, $flag | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_GLOBAL_RANGE) === false) {
			throw new SecurityTxtHostIpAddressNotPublicException($host, $ipAddress, $url->getUrl());
		}
	}


	/**
	 * @throws SecurityTxtNotFoundException
	 */
	private function getResult(SecurityTxtFetcherFetchHostResult $wellKnown, SecurityTxtFetcherFetchHostResult $topLevel, bool $requireTopLevelLocation): SecurityTxtFetchResult
	{
		$errors = $warnings = [];
		$wellKnownContents = $wellKnown->isRegularHtmlPage() || $wellKnown->isTruncated() ? null : $wellKnown->getContents();
		$topLevelContents = $topLevel->isRegularHtmlPage() || $topLevel->isTruncated() ? null : $topLevel->getContents();
		if ($wellKnownContents === null && $topLevelContents === null) {
			throw new SecurityTxtNotFoundException([$wellKnown, $topLevel], $this->redirects);
		} elseif ($wellKnownContents !== null && $topLevelContents === null) {
			if ($requireTopLevelLocation) {
				$warnings[] = new SecurityTxtWellKnownPathOnly();
			}
			$result = $wellKnown;
			$contents = $wellKnownContents;
		} elseif ($wellKnownContents === null) {
			$errors[] = new SecurityTxtTopLevelPathOnly();
			$result = $topLevel;
			$contents = $topLevelContents;
		} elseif ($wellKnownContents !== $topLevelContents) {
			if ($topLevelContents === null) {
				throw new LogicException('This should not happen');
			}
			if ($wellKnown->getFinalUrl() !== $topLevel->getFinalUrl()) {
				$warnings[] = new SecurityTxtTopLevelDiffers($wellKnownContents, $topLevelContents);
			}
			$result = $wellKnown;
			$contents = $wellKnownContents;
		} else {
			$result = $wellKnown;
			$contents = $wellKnownContents;
		}
		$this->callOnCallback($this->onFinalUrl, $result->getFinalUrl());

		$contentTypeHeader = $result->getContentType();
		if ($contentTypeHeader === null || $contentTypeHeader->getLowercaseContentType() !== SecurityTxtContentType::CONTENT_TYPE) {
			$errors[] = new SecurityTxtContentTypeInvalid($result->getUrl(), $contentTypeHeader?->getContentType());
		} elseif ($contentTypeHeader->getLowercaseCharsetParameter() !== SecurityTxtContentType::CHARSET_PARAMETER) {
			$errors[] = new SecurityTxtContentTypeWrongCharset($result->getUrl(), $contentTypeHeader->getContentType(), $contentTypeHeader->getCharsetParameter());
		}
		return new SecurityTxtFetchResult(
			$result->getUrl(),
			$result->getFinalUrl(),
			$this->redirects,
			$contents,
			$result->isTruncated(),
			$this->splitLines->splitLines($contents),
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
	 * @throws SecurityTxtConnectedToWrongIpAddressException
	 * @throws SecurityTxtHostIpAddressInvalidException
	 * @throws SecurityTxtHostIpAddressNotPublicException
	 * @throws SecurityTxtHostIpAddressInvalidTypeException
	 * @throws SecurityTxtHostIpAddressNotFoundException
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtOnlyIpv6HostButIpv6DisabledException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtUrlNotFoundException
	 * @throws SecurityTxtUrlNoSchemeException
	 * @throws SecurityTxtUrlUnsupportedSchemeException
	 * @throws SecurityTxtCannotParseHostnameException
	 */
	private function redirect(string $url, string $originalUrl, SecurityTxtFetcherResponse $response, string &$finalUrl, bool $noIpv6): SecurityTxtFetcherResponse
	{
		$location = $response->getHeader('Location');
		if ($location === null) {
			throw new SecurityTxtNoLocationHeaderException($url, $response->getHttpCode());
		} else {
			$previousUrl = isset($this->redirects[$originalUrl]) && $this->redirects[$originalUrl] !== [] ? $this->redirects[$originalUrl][array_key_last($this->redirects[$originalUrl])] : $originalUrl;
			$this->callOnCallback($this->onRedirect, $previousUrl, $location);
			$this->redirects[$originalUrl][] = $location;
			$finalUrl = $location = $this->urlParser->getRedirectUrl($location, $url);
			if (count($this->redirects[$originalUrl]) > $this->maxAllowedRedirects) {
				throw new SecurityTxtTooManyRedirectsException($url, $this->redirects[$originalUrl], $this->maxAllowedRedirects);
			}
			return $this->getResponse(new SecurityTxtFetcherUrl($location, $this->getRedirects($originalUrl)), $this->urlParser->getHostFromUrl($location), $originalUrl, $finalUrl, $noIpv6);
		}
	}


	/**
	 * @return list<string>
	 */
	private function getRedirects(string $url): array
	{
		$redirects = $this->redirects[$url] ?? [];
		if ($redirects !== []) {
			array_unshift($redirects, $url);
		}
		return $redirects;
	}

}
