<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtThrowable;
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

	public function __construct(
		private readonly SecurityTxtParser $parser,
		private readonly SecurityTxtUrlParser $urlParser,
		private readonly ConsolePrinter $printer,
		private readonly SecurityTxtFetcher $fetcher,
	) {
		$this->fetcher->addOnFetchUrl(
			function (string $url): void {
				$this->printer->info('Loading security.txt from ' . $this->printer->colorBold($url));
			},
		);
		$this->fetcher->addOnRedirect(
			function (string $url): void {
				$this->printer->info('Redirected to ' . $this->printer->colorBold($url));
			},
		);
		$this->fetcher->addOnUrlNotFound(
			function (string $url): void {
				$this->printer->info('Not found ' . $this->printer->colorBold($url));
			},
		);
	}


	private function printResult(SecurityTxtThrowable $throwable, ?int $line = null): void
	{
		$message = sprintf(
			'%s%s%s (How to fix: %s%s)',
			$line ? 'on line ' : '',
			$line ? $this->printer->colorBold((string)$line) . ': ' : '',
			$throwable->getMessage(),
			$throwable->getHowToFix(),
			$throwable->getCorrectValue() ? ', e.g. ' . $throwable->getCorrectValue() : '',
		);
		if ($throwable instanceof SecurityTxtError) {
			$this->printer->error($message);
		} else {
			$this->printer->warning($message);
		}
	}


	/**
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtHostnameException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtCannotReadUrlException
	 */
	public function check(string $url, ?int $expiresWarningThreshold = null, bool $strictMode = false, bool $noIpv6 = false): bool
	{
		$host = $this->urlParser->getHostFromUrl($url);
		$this->printer->info('Parsing security.txt for ' . $this->printer->colorBold($host));
		$parseResult = $this->parser->parseUrl($host, $noIpv6);

		foreach ($parseResult->getFetchErrors() as $error) {
			$this->printResult($error);
		}
		foreach ($parseResult->getParseErrors() as $line => $errors) {
			foreach ($errors as $error) {
				$this->printResult($error, $line);
			}
		}
		foreach ($parseResult->getFileErrors() as $error) {
			$this->printResult($error);
		}
		foreach ($parseResult->getFetchWarnings() as $warning) {
			$this->printResult($warning);
		}
		foreach ($parseResult->getParseWarnings() as $line => $warnings) {
			foreach ($warnings as $warning) {
				$this->printResult($warning, $line);
			}
		}
		foreach ($parseResult->getFileWarnings() as $warning) {
			$this->printResult($warning);
		}

		$expires = $parseResult->getSecurityTxt()->getExpires();
		$expiresSoon = $expiresWarningThreshold !== null && $expires?->inDays() < $expiresWarningThreshold;
		if ($expires !== null) {
			$days = $expires->inDays();
			$expiresDate = $expires->getDateTime()->format(DATE_RFC3339);
			if ($expires->isExpired()) {
				$this->printer->error($this->printer->colorRed('The file has expired ' . abs($days) . ' ' . ($days === 1 ? 'day' : 'days') . ' ago') . " ({$expiresDate})");
			} elseif ($expiresSoon) {
				$this->printer->error($this->printer->colorRed("The file will expire very soon in {$days} " . ($days === 1 ? 'day' : 'days')) . " ({$expiresDate})");
			} else {
				$this->printer->info($this->printer->colorGreen("The file will expire in {$days} " . ($days === 1 ? 'day' : 'days')) . " ({$expiresDate})");
			}
		}
		$signatureVerifyResult = $parseResult->getSecurityTxt()->getSignatureVerifyResult();
		if ($signatureVerifyResult) {
			$this->printer->info(sprintf(
				'%s, key %s, signed on %s',
				$this->printer->colorGreen('Signature valid'),
				$signatureVerifyResult->getKeyFingerprint(),
				$signatureVerifyResult->getDate()->format(DATE_RFC3339),
			));
		}
		return !$expires?->isExpired() && !$expiresSoon && !$parseResult->hasErrors() && (!$strictMode || !$parseResult->hasWarnings());
	}

}
