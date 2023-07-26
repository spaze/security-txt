<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Closure;
use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotReadUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostnameException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;

class SecurityTxtCheckHost
{

	/** @var null|Closure(string): void */
	private ?Closure $onUrl = null;

	/** @var null|Closure(string, string): void */
	private ?Closure $onRedirect = null;

	/** @var null|Closure(string): void */
	private ?Closure $onUrlNotFound = null;

	/** @var null|Closure(positive-int, DateTimeImmutable): void */
	private ?Closure $onIsExpired = null;

	/** @var null|Closure(positive-int, DateTimeImmutable): void */
	private ?Closure $onExpiresSoon = null;

	/** @var null|Closure(positive-int, DateTimeImmutable): void */
	private ?Closure $onExpires = null;

	/** @var null|Closure(string): void */
	private ?Closure $onHost = null;

	/** @var null|Closure(string, DateTimeImmutable): void */
	private ?Closure $onValidSignature = null;

	/** @var null|Closure(?int, string, string, ?string): void */
	private ?Closure $onFetchError = null;

	/** @var null|Closure(?int, string, string, ?string): void */
	private ?Closure $onParseError = null;

	/** @var null|Closure(?int, string, string, ?string): void */
	private ?Closure $onFileError = null;

	/** @var null|Closure(?int, string, string, ?string): void */
	private ?Closure $onFetchWarning = null;

	/** @var null|Closure(?int, string, string, ?string): void */
	private ?Closure $onParseWarning = null;

	/** @var null|Closure(?int, string, string, ?string): void */
	private ?Closure $onFileWarning = null;


	public function __construct(
		private readonly SecurityTxtParser $parser,
		private readonly SecurityTxtUrlParser $urlParser,
		private readonly SecurityTxtFetcher $fetcher,
	) {
	}


	/**
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtHostnameException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtCannotReadUrlException
	 */
	public function check(string $url, ?int $expiresWarningThreshold = null, bool $strictMode = false, bool $noIpv6 = false): SecurityTxtCheckHostResult
	{
		$this->initFetcherCallbacks();

		$host = $this->urlParser->getHostFromUrl($url);
		$this->callOnCallback($this->onHost, $host);
		$parseResult = $this->parser->parseUrl($host, $noIpv6);

		foreach ($parseResult->getFetchErrors() as $error) {
			$this->error($this->onFetchError, $error);
		}
		foreach ($parseResult->getParseErrors() as $line => $errors) {
			foreach ($errors as $error) {
				$this->error($this->onParseError, $error, $line);
			}
		}
		foreach ($parseResult->getFileErrors() as $error) {
			$this->error($this->onFileError, $error);
		}
		foreach ($parseResult->getFetchWarnings() as $warning) {
			$this->warning($this->onFetchWarning, $warning);
		}
		foreach ($parseResult->getParseWarnings() as $line => $warnings) {
			foreach ($warnings as $warning) {
				$this->warning($this->onParseWarning, $warning, $line);
			}
		}
		foreach ($parseResult->getFileWarnings() as $warning) {
			$this->warning($this->onFileWarning, $warning);
		}

		$expires = $parseResult->getSecurityTxt()->getExpires();
		$expiresSoon = $expiresWarningThreshold !== null && $expires?->inDays() < $expiresWarningThreshold;
		if ($expires !== null) {
			$days = $expires->inDays();
			if ($expires->isExpired()) {
				$this->callOnCallback($this->onIsExpired, abs($days), $expires->getDateTime());
			} elseif ($expiresSoon) {
				$this->callOnCallback($this->onExpiresSoon, $days, $expires->getDateTime());
			} else {
				$this->callOnCallback($this->onExpires, $days, $expires->getDateTime());
			}
		}
		$signatureVerifyResult = $parseResult->getSecurityTxt()->getSignatureVerifyResult();
		if ($signatureVerifyResult) {
			$this->callOnCallback($this->onValidSignature, $signatureVerifyResult->getKeyFingerprint(), $signatureVerifyResult->getDate());
		}

		return new SecurityTxtCheckHostResult(
			$host,
			$parseResult->getFetchResult()?->getRedirects() ?? [],
			$parseResult->getFetchResult()?->getConstructedUrl() ?? null,
			$parseResult->getFetchResult()?->getFinalUrl() ?? null,
			$parseResult->getFetchErrors(),
			$parseResult->getFetchWarnings(),
			$parseResult->getParseErrors(),
			$parseResult->getParseWarnings(),
			$parseResult->getFileErrors(),
			$parseResult->getFileWarnings(),
			$parseResult->getSecurityTxt(),
			$expiresSoon,
			$expires?->isExpired(),
			$days ?? null,
			!$expires?->isExpired() && !$expiresSoon && !$parseResult->hasErrors() && (!$strictMode || !$parseResult->hasWarnings()),
			$strictMode,
		);
	}


	private function initFetcherCallbacks(): void
	{
		$this->fetcher->addOnUrl(
			function (string $url): void {
				$this->callOnCallback($this->onUrl, $url);
			},
		);
		$this->fetcher->addOnRedirect(
			function (string $url, string $destination): void {
				$this->callOnCallback($this->onRedirect, $url, $destination);
			},
		);
		$this->fetcher->addOnUrlNotFound(
			function (string $url): void {
				$this->callOnCallback($this->onUrlNotFound, $url);
			},
		);
	}


	private function error(?Closure $handler, SecurityTxtError $error, ?int $line = null): void
	{
		$this->callOnCallback($handler, $line, $error->getMessage(), $error->getHowToFix(), $error->getCorrectValue());
	}


	private function warning(?Closure $handler, SecurityTxtWarning $warning, ?int $line = null): void
	{
		$this->callOnCallback($handler, $line, $warning->getMessage(), $warning->getHowToFix(), $warning->getCorrectValue());
	}


	private function callOnCallback(?Closure $onCallback, string|int|DateTimeImmutable|null ...$params): void
	{
		if ($onCallback) {
			$onCallback(...$params);
		}
	}


	/**
	 * @param null|Closure(string $url): void $onUrl
	 */
	public function addOnUrl(?Closure $onUrl): void
	{
		$this->onUrl = $onUrl;
	}


	/**
	 * @param null|Closure(string $url, string $destination): void $onRedirect
	 */
	public function addOnRedirect(?Closure $onRedirect): void
	{
		$this->onRedirect = $onRedirect;
	}


	/**
	 * @param null|Closure(string $url): void $onUrlNotFound
	 */
	public function addOnUrlNotFound(?Closure $onUrlNotFound): void
	{
		$this->onUrlNotFound = $onUrlNotFound;
	}


	/**
	 * @param null|Closure(positive-int $daysAgo, DateTimeImmutable $expiryDate): void $onIsExpired
	 */
	public function addOnIsExpired(?Closure $onIsExpired): void
	{
		$this->onIsExpired = $onIsExpired;
	}


	/**
	 * @param null|Closure(positive-int $inDays, DateTimeImmutable $expiryDate): void $onExpiresSoon
	 */
	public function addOnExpiresSoon(?Closure $onExpiresSoon): void
	{
		$this->onExpiresSoon = $onExpiresSoon;
	}


	/**
	 * @param null|Closure(positive-int $inDays, DateTimeImmutable $expiryDate): void $onExpires
	 */
	public function addOnExpires(?Closure $onExpires): void
	{
		$this->onExpires = $onExpires;
	}


	/**
	 * @param null|Closure(string $host): void $onParse
	 */
	public function addOnHost(?Closure $onParse): void
	{
		$this->onHost = $onParse;
	}


	/**
	 * @param null|Closure(string $keyFingerprint, DateTimeImmutable $signatureDate): void $onValidSignature
	 */
	public function addOnValidSignature(?Closure $onValidSignature): void
	{
		$this->onValidSignature = $onValidSignature;
	}


	/**
	 * @param null|Closure(?int, string, string, ?string): void $onFetchError
	 */
	public function addOnFetchError(?Closure $onFetchError): void
	{
		$this->onFetchError = $onFetchError;
	}


	/**
	 * @param null|Closure(?int, string, string, ?string): void $onParseError
	 */
	public function addOnParseError(?Closure $onParseError): void
	{
		$this->onParseError = $onParseError;
	}


	/**
	 * @param null|Closure(?int, string, string, ?string): void $onFileError
	 */
	public function addOnFileError(?Closure $onFileError): void
	{
		$this->onFileError = $onFileError;
	}


	/**
	 * @param null|Closure(?int, string, string, ?string): void $onFetchWarning
	 */
	public function addOnFetchWarning(?Closure $onFetchWarning): void
	{
		$this->onFetchWarning = $onFetchWarning;
	}


	/**
	 * @param null|Closure(?int, string, string, ?string): void $onParseWarning
	 */
	public function addOnParseWarning(?Closure $onParseWarning): void
	{
		$this->onParseWarning = $onParseWarning;
	}


	/**
	 * @param null|Closure(?int, string, string, ?string): void $onFileWarning
	 */
	public function addOnFileWarning(?Closure $onFileWarning): void
	{
		$this->onFileWarning = $onFileWarning;
	}

}
