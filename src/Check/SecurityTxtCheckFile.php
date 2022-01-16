<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtThrowable;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;

class SecurityTxtCheckFile
{

	private const RED = "\033[1;31m";
	private const GREEN = "\033[1;32m";
	private const BOLD = "\033[1m";
	private const DARK = "\033[1;30m";
	private const CLEAR = "\033[0m";

	private const STATUS_OK = 0;
	private const STATUS_ERROR = 1;
	private const STATUS_NO_FILE = 2;
	private const STATUS_FILE_ERROR = 3;


	public function __construct(
		private SecurityTxtParser $parser,
		private string $scriptName,
	) {
	}


	private function printResult(SecurityTxtThrowable $throwable, ?int $line = null): void
	{
		$message = sprintf(
			'%s%s%s%s: %s (How to fix: %s%s)',
			$line ? 'on line ' : '',
			$line ? self::BOLD : '',
			$line ?: '',
			$line ? self::CLEAR : '',
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
			$this->info("Usage: {$this->scriptName} <file> [days]\nThe check will return 1 instead of 0 if the file has expired or expires in less than [days]");
			exit(self::STATUS_NO_FILE);
		}

		$contents = file_get_contents($file);
		if ($contents === false) {
			exit(self::STATUS_FILE_ERROR);
		}

		$this->info('parsing ' . self::BOLD . $file . self::CLEAR);

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

		$expires = $parseResult->getSecurityTxt()->getExpires();
		$expiresSoon = $expiresWarningThreshold !== null && $expires?->inDays() < $expiresWarningThreshold;
		if ($expires !== null) {
			$days = $expires->inDays();
			$expiresDate = $expires->getDateTime()->format(DATE_RFC3339);
			if ($expires->isExpired()) {
				$this->error(sprintf(
					'%sThe file has expired %s %s ago%s (%s)',
					self::RED,
					abs($days),
					$days === 1 ? 'day' : 'days',
					self::CLEAR,
					$expiresDate,
				));
			} elseif ($expiresSoon) {
				$this->error(sprintf(
					'%sThe file will expire very soon in %s %s%s (%s)',
					self::RED,
					$days,
					$days === 1 ? 'day' : 'days',
					self::CLEAR,
					$expiresDate,
				));
			} else {
				$this->info(sprintf(
					'%sThe file will expire in %s %s%s (%s)',
					self::GREEN,
					$days,
					$days === 1 ? 'day' : 'days',
					self::CLEAR,
					$expiresDate,
				));
			}
		}
		$signatureVerifyResult = $parseResult->getSecurityTxt()->getSignatureVerifyResult();
		if ($signatureVerifyResult) {
			$this->info(sprintf(
				'%sSignature valid%s, key %s, signed on %s',
				self::GREEN,
				self::CLEAR,
				$signatureVerifyResult->getKeyFingerprint(),
				$signatureVerifyResult->getDate()->format(DATE_RFC3339),
			));
		}
		if ($expires?->isExpired() || $expiresSoon || $parseResult->hasErrors()) {
			$this->error(self::RED . 'Please update the file!' . self::CLEAR);
			exit(self::STATUS_ERROR);
		} else {
			exit(self::STATUS_OK);
		}
	}


	private function info(string $message): void
	{
		$this->print(self::DARK . '[Info]' . self::CLEAR, $message);
	}


	private function error(string $message): void
	{
		$this->print(self::RED . '[Error]' . self::CLEAR, $message);
	}


	private function warning(string $message): void
	{
		$this->print(self::BOLD . '[Warning]' . self::CLEAR, $message);
	}


	private function print(string $level, string $message): void
	{
		$message = str_replace("\n", "\n{$level} ", $message);
		echo "{$level} {$message}\n";
	}

}
