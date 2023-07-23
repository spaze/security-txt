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
$checkFile = new SecurityTxtCheckHost($parser, $urlParser, $consolePrinter, $fetcher);
/** @var array<int, string> $args */
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
	$valid = $checkFile->check(
		$args[1],
		empty($args[2]) ? null : (int)$args[2],
		in_array('--strict', $args, true),
		in_array('--no-ipv6', $args, true),
	);
	if (!$valid) {
		$consolePrinter->error($consolePrinter->colorRed('Please update the file!'));
		exit(CheckExitStatus::Error->value);
	} else {
		exit(CheckExitStatus::Ok->value);
	}
} catch (SecurityTxtFetcherException $e) {
	$consolePrinter->error($e->getMessage());
	exit(CheckExitStatus::FileError->value);
}
