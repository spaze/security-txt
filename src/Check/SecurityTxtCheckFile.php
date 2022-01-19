<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtThrowable;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;

class SecurityTxtCheckFile
{

	private const STATUS_OK = 0;
	private const STATUS_ERROR = 1;
	private const STATUS_NO_FILE = 2;
	private const STATUS_FILE_ERROR = 3;


	public function __construct(
		private SecurityTxtParser $parser,
		private string $scriptName,
		private bool $colors,
		private bool $strictMode,
	) {
	}


	private function printResult(SecurityTxtThrowable $throwable, ?int $line = null): void
	{
		$message = sprintf(
			'%s%s: %s (How to fix: %s%s)',
			$line ? 'on line ' : '',
			$line ? $this->colorBold((string)$line) : '',
			$throwable->getMessage(),
			$throwable->getHowToFix(),
			$throwable->getCorrectValue() ? ', e.g. ' . $throwable->getCorrectValue() : '',
		);
		if ($throwable instanceof SecurityTxtError) {
			$this->error($message);
		} else {
			$this->warning($message);
		}
	}


	public function check(?string $file = null, ?int $expiresWarningThreshold = null): never
	{
		if ($file === null) {
			$this->info("Usage: {$this->scriptName} <file> [days] [--colors] [--strict] \nThe check will return 1 instead of 0 if any of the following is true: the file has expired, expires in less than <days>, has errors, has warnings when using --strict");
			exit(self::STATUS_NO_FILE);
		}

		$context = stream_context_create([
			'http' => [
				'user_agent' => str_replace('\\', '/', __METHOD__),
			],
		]);
		$contents = file_get_contents($file, context: $context);
		if ($contents === false) {
			exit(self::STATUS_FILE_ERROR);
		}

		$this->info('parsing ' . $this->colorBold($file));

		$parseResult = $this->parser->parseString($contents);
		foreach ($parseResult->getParseErrors() as $line => $errors) {
			foreach ($errors as $error) {
				$this->printResult($error, $line);
			}
		}
		foreach ($parseResult->getFileErrors() as $error) {
			$this->printResult($error);
		}
		foreach ($parseResult->getParseWarnings() as $line => $warnings) {
			foreach ($warnings as $warning) {
				$this->printResult($warning, $line);
			}
		}
		foreach ($parseResult->getFileWarnings() as $error) {
			$this->printResult($error);
		}

		$expires = $parseResult->getSecurityTxt()->getExpires();
		$expiresSoon = $expiresWarningThreshold !== null && $expires?->inDays() < $expiresWarningThreshold;
		if ($expires !== null) {
			$days = $expires->inDays();
			$expiresDate = $expires->getDateTime()->format(DATE_RFC3339);
			if ($expires->isExpired()) {
				$this->error($this->colorRed('The file has expired ' . abs($days) . ' ' . ($days === 1 ? 'day' : 'days') . ' ago') . " ({$expiresDate})");
			} elseif ($expiresSoon) {
				$this->error($this->colorRed("The file will expire very soon in {$days} " . ($days === 1 ? 'day' : 'days')) . " ({$expiresDate})");
			} else {
				$this->info($this->colorGreen("The file will expire in {$days} " . ($days === 1 ? 'day' : 'days')) . " ({$expiresDate})");
			}
		}
		$signatureVerifyResult = $parseResult->getSecurityTxt()->getSignatureVerifyResult();
		if ($signatureVerifyResult) {
			$this->info(sprintf(
				'%s, key %s, signed on %s',
				$this->colorGreen('Signature valid'),
				$signatureVerifyResult->getKeyFingerprint(),
				$signatureVerifyResult->getDate()->format(DATE_RFC3339),
			));
		}
		if ($expires?->isExpired() || $expiresSoon || $parseResult->hasErrors() || ($this->strictMode && $parseResult->hasWarnings())) {
			$this->error($this->colorRed('Please update the file!'));
			exit(self::STATUS_ERROR);
		} else {
			exit(self::STATUS_OK);
		}
	}


	private function info(string $message): void
	{
		$this->print($this->colorDarkGray('[Info]'), $message);
	}


	private function error(string $message): void
	{
		$this->print($this->colorRed('[Error]'), $message);
	}


	private function warning(string $message): void
	{
		$this->print($this->colorBold('[Warning]'), $message);
	}


	private function print(string $level, string $message): void
	{
		$message = str_replace("\n", "\n{$level} ", $message);
		echo "{$level} {$message}\n";
	}


	private function colorRed(string $message): string
	{
		return $this->color("\033[1;31m", $message);
	}


	private function colorGreen(string $message): string
	{
		return $this->color("\033[1;32m", $message);
	}


	private function colorBold(string $message): string
	{
		return $this->color("\033[1m", $message);
	}


	private function colorDarkGray(string $message): string
	{
		return $this->color("\033[1;90m", $message);
	}


	private function color(string $color, string $message): string
	{
		return sprintf('%s%s%s', $this->colors ? $color : '', $message, $this->colors ? "\033[0m" : '');
	}

}
