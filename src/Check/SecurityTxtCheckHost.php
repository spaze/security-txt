<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

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

	/** @var list<callable(string): void> */
	private array $onUrl = [];

	/** @var list<callable(string, string): void> */
	private array $onRedirect = [];

	/** @var list<callable(string): void> */
	private array $onUrlNotFound = [];

	/** @var list<callable(positive-int, DateTimeImmutable): void> */
	private array $onIsExpired = [];

	/** @var list<callable(positive-int, DateTimeImmutable): void> */
	private array $onExpiresSoon = [];

	/** @var list<callable(positive-int, DateTimeImmutable): void> */
	private array $onExpires = [];

	/** @var list<callable(string): void> */
	private array $onHost = [];

	/** @var list<callable(string, DateTimeImmutable): void> */
	private array $onValidSignature = [];

	/** @var list<callable(?int, string, string, ?string): void> */
	private array $onFetchError = [];

	/** @var list<callable(?int, string, string, ?string): void> */
	private array $onParseError = [];

	/** @var list<callable(?int, string, string, ?string): void> */
	private array $onFileError = [];

	/** @var list<callable(?int, string, string, ?string): void> */
	private array $onFetchWarning = [];

	/** @var list<callable(?int, string, string, ?string): void> */
	private array $onParseWarning = [];

	/** @var list<callable(?int, string, string, ?string): void> */
	private array $onFileWarning = [];


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


	/**
	 * @param list<callable(?int, string, string, ?string): void> $handlers
	 */
	private function error(array $handlers, SecurityTxtError $error, ?int $line = null): void
	{
		$this->callOnCallback($handlers, $line, $error->getMessage(), $error->getHowToFix(), $error->getCorrectValue());
	}


	/**
	 * @param list<callable(?int, string, string, ?string): void> $handlers
	 */
	private function warning(array $handlers, SecurityTxtWarning $warning, ?int $line = null): void
	{
		$this->callOnCallback($handlers, $line, $warning->getMessage(), $warning->getHowToFix(), $warning->getCorrectValue());
	}


	/**
	 * @param list<callable> $onCallbacks
	 */
	private function callOnCallback(array $onCallbacks, string|int|DateTimeImmutable|null ...$params): void
	{
		foreach ($onCallbacks as $onCallback) {
			$onCallback(...$params);
		}
	}


	/**
	 * @param callable(string $url): void $onUrl
	 */
	public function addOnUrl(callable $onUrl): void
	{
		$this->onUrl[] = $onUrl;
	}


	/**
	 * @param callable(string $url, string $destination): void $onRedirect
	 */
	public function addOnRedirect(callable $onRedirect): void
	{
		$this->onRedirect[] = $onRedirect;
	}


	/**
	 * @param callable(string $url): void $onUrlNotFound
	 */
	public function addOnUrlNotFound(callable $onUrlNotFound): void
	{
		$this->onUrlNotFound[] = $onUrlNotFound;
	}


	/**
	 * @param callable(positive-int $daysAgo, DateTimeImmutable $expiryDate): void $onIsExpired
	 */
	public function addOnIsExpired(callable $onIsExpired): void
	{
		$this->onIsExpired[] = $onIsExpired;
	}


	/**
	 * @param callable(positive-int $inDays, DateTimeImmutable $expiryDate): void $onExpiresSoon
	 */
	public function addOnExpiresSoon(callable $onExpiresSoon): void
	{
		$this->onExpiresSoon[] = $onExpiresSoon;
	}


	/**
	 * @param callable(positive-int $inDays, DateTimeImmutable $expiryDate): void $onExpires
	 */
	public function addOnExpires(callable $onExpires): void
	{
		$this->onExpires[] = $onExpires;
	}


	/**
	 * @param callable(string $host): void $onParse
	 */
	public function addOnHost(callable $onParse): void
	{
		$this->onHost[] = $onParse;
	}


	/**
	 * @param callable(string $keyFingerprint, DateTimeImmutable $signatureDate): void $onValidSignature
	 */
	public function addOnValidSignature(callable $onValidSignature): void
	{
		$this->onValidSignature[] = $onValidSignature;
	}


	/**
	 * @param callable(?int, string, string, ?string): void $onFetchError
	 */
	public function addOnFetchError(callable $onFetchError): void
	{
		$this->onFetchError[] = $onFetchError;
	}


	/**
	 * @param callable(?int, string, string, ?string): void $onParseError
	 */
	public function addOnParseError(callable $onParseError): void
	{
		$this->onParseError[] = $onParseError;
	}


	/**
	 * @param callable(?int, string, string, ?string): void $onFileError
	 */
	public function addOnFileError(callable $onFileError): void
	{
		$this->onFileError[] = $onFileError;
	}


	/**
	 * @param callable(?int, string, string, ?string): void $onFetchWarning
	 */
	public function addOnFetchWarning(callable $onFetchWarning): void
	{
		$this->onFetchWarning[] = $onFetchWarning;
	}


	/**
	 * @param callable(?int, string, string, ?string): void $onParseWarning
	 */
	public function addOnParseWarning(callable $onParseWarning): void
	{
		$this->onParseWarning[] = $onParseWarning;
	}


	/**
	 * @param callable(?int, string, string, ?string): void $onFileWarning
	 */
	public function addOnFileWarning(callable $onFileWarning): void
	{
		$this->onFileWarning[] = $onFileWarning;
	}

}
