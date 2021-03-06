#!/usr/bin/env php
<?php
declare(strict_types = 1);

use Spaze\SecurityTxt\Check\ConsolePrinter;
use Spaze\SecurityTxt\Check\SecurityTxtCheckHost;
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
/** @var array<int, string> $args */
$args = is_array($_SERVER['argv']) ? $_SERVER['argv'] : [];
$consolePrinter = new ConsolePrinter(in_array('--colors', $args, true));
$checkFile = new SecurityTxtCheckHost(
	$parser,
	$urlParser,
	$consolePrinter,
	$args[0],
	in_array('--strict', $args, true),
);
$checkFile->check($args[1] ?? null, empty($args[2]) ? null : (int)$args[2]);
