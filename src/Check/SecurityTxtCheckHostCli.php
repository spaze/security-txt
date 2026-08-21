<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Closure;
use DateTimeImmutable;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Uri\WhatWg\Url;

final class SecurityTxtCheckHostCli
{

	private bool $verbose = false;


	/**
	 * @param Closure(int): void $exit
	 */
	public function __construct(
		private readonly ConsolePrinter $consolePrinter,
		private readonly SecurityTxtCheckHost $checkHost,
		private readonly Closure $exit,
	) {
		$this->initCheckHostCallbacks();
	}


	public function check(
		?Url $url,
		?int $expiresWarningThreshold,
		bool $colors,
		bool $verbose,
		bool $strictMode,
		bool $requireTopLevelLocation,
		bool $noIpv6,
		bool $showUsageHelp,
		string $usageHelp,
	): void {
		$this->verbose = $verbose;
		$this->consolePrinter->setColors($colors);
		if ($showUsageHelp) {
			$this->printUsageHelp($usageHelp);
			$this->exit(CheckExitStatus::Ok);
			return;
		} elseif ($url === null) {
			$this->printUsageHelp($usageHelp);
			$this->exit(CheckExitStatus::NoFile);
			return;
		}
		try {
			$checkResult = $this->checkHost->check(
				$url,
				$expiresWarningThreshold,
				$strictMode,
				$requireTopLevelLocation,
				$noIpv6,
			);
			if (!$checkResult->isValid()) {
				$this->consolePrinter->error('<red>The file is invalid</red>');
				$this->exit(CheckExitStatus::Error);
			} else {
				$this->consolePrinter->ok('<green>The file is valid</green>');
				$this->exit(CheckExitStatus::Ok);
			}
		} catch (SecurityTxtFetcherException $e) {
			$this->consolePrinter->error($e->getMessageFormat(), ...$e->getMessageValues());
			$this->exit(CheckExitStatus::FileError);
		}
	}


	private function exit(CheckExitStatus $exitStatus): void
	{
		($this->exit)($exitStatus->value);
	}


	/**
	 * The text comes from whoever calls `check()`, so it goes in as a value, and a line at a time because a value cannot carry a newline.
	 */
	private function printUsageHelp(string $usageHelp): void
	{
		foreach (explode("\n", $usageHelp) as $line) {
			$this->consolePrinter->info('%s', $line);
		}
	}


	/**
	 * Format and values are built together because they have to agree on how many placeholders there are, and nothing checks that they do: a format with one too many kills the run with a `ValueError`, one too few drops a value from the message without saying so.
	 *
	 * @return array{0:literal-string, 1:list<string>}
	 */
	private function getViolationMessage(?int $line, string $message, string $howToFix, ?string $correctValue): array
	{
		$format = '%s (How to fix: %s';
		$values = [$message, $howToFix];
		if ($line !== null) {
			$format = 'on line <b>%s</b>: ' . $format;
			array_unshift($values, (string)$line);
		}
		if ($correctValue !== null) {
			$format .= ', e.g. %s';
			$values[] = $correctValue;
		}
		return [$format . ')', $values];
	}


	private function initCheckHostCallbacks(): void
	{
		$this->checkHost->addOnUrl(
			function (string $url): void {
				if ($this->verbose) {
					$this->consolePrinter->info('Loading security.txt from <b>%s</b>', $url);
				}
			},
		);
		$this->checkHost->addOnRedirect(
			function (string $url, string $destination): void {
				if ($this->verbose) {
					$this->consolePrinter->info('Redirected from <b>%s</b> to <b>%s</b>', $url, $destination);
				}
			},
		);
		$this->checkHost->addOnUrlNotFound(
			function (string $url): void {
				if ($this->verbose) {
					$this->consolePrinter->info('Not found <b>%s</b>', $url);
				}
			},
		);
		$this->checkHost->addOnFinalUrl(
			function (string $url): void {
				$this->consolePrinter->info('Using <b>%s</b>', $url);
			},
		);
		$this->checkHost->addOnIsExpired(
			function (int $daysAgo, DateTimeImmutable $expiryDate): void {
				$this->consolePrinter->error(
					'<red>The file has expired %s ' . ($daysAgo === 1 ? 'day' : 'days') . ' ago</red> (%s)',
					(string)$daysAgo,
					$expiryDate->format(DATE_RFC3339),
				);
			},
		);
		$this->checkHost->addOnExpires(
			function (int $inDays, DateTimeImmutable $expiryDate): void {
				$this->consolePrinter->ok(
					'The file will expire in %s ' . ($inDays === 1 ? 'day' : 'days') . ' (%s)',
					(string)$inDays,
					$expiryDate->format(DATE_RFC3339),
				);
			},
		);
		$this->checkHost->addOnHost(
			function (string $host): void {
				$this->consolePrinter->info('Parsing security.txt for <b>%s</b>', $host);
			},
		);
		$this->checkHost->addOnValidSignature(
			function (string $keyFingerprint, DateTimeImmutable $signatureDate): void {
				$this->consolePrinter->ok(
					'Signature valid, key %s, signed on %s',
					$keyFingerprint,
					$signatureDate->format(DATE_RFC3339),
				);
			},
		);
		$onError = function (?int $line, string $message, string $howToFix, ?string $correctValue): void {
			[$format, $values] = $this->getViolationMessage($line, $message, $howToFix, $correctValue);
			$this->consolePrinter->error($format, ...$values);
		};
		$onWarning = function (?int $line, string $message, string $howToFix, ?string $correctValue): void {
			[$format, $values] = $this->getViolationMessage($line, $message, $howToFix, $correctValue);
			$this->consolePrinter->warning($format, ...$values);
		};
		$this->checkHost->addOnFetchError($onError);
		$this->checkHost->addOnLineError($onError);
		$this->checkHost->addOnFileError($onError);
		$this->checkHost->addOnFetchWarning($onWarning);
		$this->checkHost->addOnLineWarning($onWarning);
		$this->checkHost->addOnFileWarning($onWarning);
	}

}
