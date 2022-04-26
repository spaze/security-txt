<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtThrowable;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostnameException;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;

class SecurityTxtCheckHost
{

	private const STATUS_OK = 0;
	private const STATUS_ERROR = 1;
	private const STATUS_NO_FILE = 2;
	private const STATUS_FILE_ERROR = 3;


	public function __construct(
		private SecurityTxtParser $parser,
		private SecurityTxtUrlParser $urlParser,
		private readonly ConsolePrinter $printer,
		private string $scriptName,
		private bool $strictMode,
	) {
		$fetcher = $this->parser->getFetcher();
		$fetcher->addOnFetchUrl(
			function (string $url): void {
				$this->printer->info('Loading security.txt from ' . $this->printer->colorBold($url));
			},
		);
		$fetcher->addOnRedirect(
			function (string $url): void {
				$this->printer->info('Redirected to ' . $this->printer->colorBold($url));
			},
		);
		$fetcher->addOnUrlNotFound(
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


	public function check(?string $url = null, ?int $expiresWarningThreshold = null): never
	{
		if ($url === null) {
			$this->printer->info("Usage: {$this->scriptName} <url or hostname> [days] [--colors] [--strict] \nThe check will return 1 instead of 0 if any of the following is true: the file has expired, expires in less than <days>, has errors, has warnings when using --strict");
			exit(self::STATUS_NO_FILE);
		}

		try {
			$host = $this->urlParser->getHostFromUrl($url);
		} catch (SecurityTxtHostnameException $e) {
			$this->printer->error($e->getMessage());
			exit(self::STATUS_FILE_ERROR);
		}
		$this->printer->info('Parsing security.txt for ' . $this->printer->colorBold($host));

		try {
			$parseResult = $this->parser->parseUrl($host);
		} catch (SecurityTxtFetcherException $e) {
			$this->printer->error($e->getMessage());
			exit(self::STATUS_FILE_ERROR);
		}

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
		if ($expires?->isExpired() || $expiresSoon || $parseResult->hasErrors() || ($this->strictMode && $parseResult->hasWarnings())) {
			$this->printer->error($this->printer->colorRed('Please update the file!'));
			exit(self::STATUS_ERROR);
		}
		exit(self::STATUS_OK);
	}

}
