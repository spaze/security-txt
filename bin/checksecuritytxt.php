#!/usr/bin/env php
<?php
declare(strict_types = 1);

use Spaze\SecurityTxt\Check\CheckExitStatus;
use Spaze\SecurityTxt\Check\ConsolePrinter;
use Spaze\SecurityTxt\Check\SecurityTxtCheckHost;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;

$autoloadFiles = [
	__DIR__ . '/../vendor/autoload.php',
	__DIR__ . '/../../../autoload.php',
];

$autoloadLoaded = false;
foreach ($autoloadFiles as $autoloadFile) {
	if (is_file($autoloadFile)) {
		require_once $autoloadFile;
		$autoloadLoaded = true;
		break;
	}
}

if (!$autoloadLoaded) {
	fwrite(STDERR, "Install packages using Composer.\n");
	exit(254);
}

$validator = new SecurityTxtValidator();
$signature = new SecurityTxtSignature();
$fetcher = new SecurityTxtFetcher();
$parser = new SecurityTxtParser($validator, $signature, $fetcher);
$urlParser = new SecurityTxtUrlParser();
$consolePrinter = new ConsolePrinter();
$checkFile = new SecurityTxtCheckHost($parser, $urlParser, $fetcher);
$checkFile->addOnUrl(
	function (string $url) use ($consolePrinter): void {
		$consolePrinter->info('Loading security.txt from ' . $consolePrinter->colorBold($url));
	},
);
$checkFile->addOnRedirect(
	function (string $url) use ($consolePrinter): void {
		$consolePrinter->info('Redirected to ' . $consolePrinter->colorBold($url));
	},
);
$checkFile->addOnUrlNotFound(
	function (string $url) use ($consolePrinter): void {
		$consolePrinter->info('Not found ' . $consolePrinter->colorBold($url));
	},
);
$checkFile->addOnIsExpired(
	function (int $daysAgo, DateTimeImmutable $expiryDate) use ($consolePrinter): void {
		$consolePrinter->error($consolePrinter->colorRed('The file has expired ' . $daysAgo . ' ' . ($daysAgo === 1 ? 'day' : 'days') . ' ago') . " ({$expiryDate->format(DATE_RFC3339)})");
	},
);
$checkFile->addOnExpiresSoon(
	function (int $inDays, DateTimeImmutable $expiryDate) use ($consolePrinter): void {
		$consolePrinter->error($consolePrinter->colorRed("The file will expire very soon in {$inDays} " . ($inDays === 1 ? 'day' : 'days')) . " ({$expiryDate->format(DATE_RFC3339)})");
	},
);
$checkFile->addOnExpires(
	function (int $inDays, DateTimeImmutable $expiryDate) use ($consolePrinter): void {
		$consolePrinter->info($consolePrinter->colorGreen("The file will expire in {$inDays} " . ($inDays === 1 ? 'day' : 'days')) . " ({$expiryDate->format(DATE_RFC3339)})");
	},
);
$checkFile->addOnHost(
	function (string $host) use ($consolePrinter): void {
		$consolePrinter->info('Parsing security.txt for ' . $consolePrinter->colorBold($host));
	},
);
$checkFile->addOnValidSignature(
	function (string $keyFingerprint, DateTimeImmutable $signatureDate) use ($consolePrinter): void {
		$consolePrinter->info(sprintf(
			'%s, key %s, signed on %s',
			$consolePrinter->colorGreen('Signature valid'),
			$keyFingerprint,
			$signatureDate->format(DATE_RFC3339),
		));
	},
);
$onError = function (?int $line, string $message, string $howToFix, ?string $correctValue) use ($consolePrinter): void {
	$consolePrinter->error(sprintf(
		'%s%s%s (How to fix: %s%s)',
		$line ? 'on line ' : '',
		$line ? $consolePrinter->colorBold((string)$line) . ': ' : '',
		$message,
		$howToFix,
		$correctValue ? ', e.g. ' . $correctValue : '',
	));
};
$onWarning = function (?int $line, string $message, string $howToFix, ?string $correctValue) use ($consolePrinter): void {
	$consolePrinter->warning(sprintf(
		'%s%s%s (How to fix: %s%s)',
		$line ? 'on line ' : '',
		$line ? $consolePrinter->colorBold((string)$line) . ': ' : '',
		$message,
		$howToFix,
		$correctValue ? ', e.g. ' . $correctValue : '',
	));
};
$checkFile->addOnFetchError($onError);
$checkFile->addOnParseError($onError);
$checkFile->addOnFileError($onError);
$checkFile->addOnFetchWarning($onWarning);
$checkFile->addOnParseWarning($onWarning);
$checkFile->addOnFileWarning($onWarning);

/** @var list<string> $args */
$args = is_array($_SERVER['argv']) ? $_SERVER['argv'] : [];
$colors = array_search('--colors', $args, true);
if ($colors) {
	$consolePrinter->enableColors();
	unset($args[$colors]);
}
if (!isset($args[1])) {
	$prologue = is_array($_SERVER['argv']) && is_string($_SERVER['argv'][0]) ? "Usage: {$_SERVER['argv'][0]}" : 'Params:';
	$consolePrinter->info("{$prologue} <url or hostname> [days] [--colors] [--strict] [--no-ipv6] \nThe check will return 1 instead of 0 if any of the following is true: the file has expired, expires in less than <days>, has errors, has warnings when using --strict");
	exit(CheckExitStatus::NoFile->value);
}

try {
	$checkResult = $checkFile->check(
		$args[1],
		empty($args[2]) ? null : (int)$args[2],
		in_array('--strict', $args, true),
		in_array('--no-ipv6', $args, true),
	);
	if (!$checkResult->isValid()) {
		$consolePrinter->error($consolePrinter->colorRed('Please update the file!'));
		exit(CheckExitStatus::Error->value);
	} else {
		exit(CheckExitStatus::Ok->value);
	}
} catch (SecurityTxtFetcherException $e) {
	$consolePrinter->error($e->getMessage());
	exit(CheckExitStatus::FileError->value);
}
