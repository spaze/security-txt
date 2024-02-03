#!/usr/bin/env php
<?php
declare(strict_types = 1);

use Spaze\SecurityTxt\Check\ConsolePrinter;
use Spaze\SecurityTxt\Check\SecurityTxtCheckHost;
use Spaze\SecurityTxt\Check\SecurityTxtCheckHostCli;
use Spaze\SecurityTxt\Check\SecurityTxtCheckHostResultFactory;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherFopenClient;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Json\SecurityTxtJson;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\SecurityTxtFactory;
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
$fopenClient = new SecurityTxtFetcherFopenClient();
$fetcher = new SecurityTxtFetcher($fopenClient);
$parser = new SecurityTxtParser($validator, $signature, $fetcher);
$urlParser = new SecurityTxtUrlParser();
$consolePrinter = new ConsolePrinter();
$securitytxtFactory = new SecurityTxtFactory();
$violationFactory = new SecurityTxtJson();
$checkHostResultFactory = new SecurityTxtCheckHostResultFactory($securitytxtFactory, $violationFactory);
$checkHost = new SecurityTxtCheckHost($parser, $urlParser, $fetcher, $checkHostResultFactory);
$checkHostCli = new SecurityTxtCheckHostCli($consolePrinter, $checkHost);

/** @var list<string> $args */
$args = is_array($_SERVER['argv']) ? $_SERVER['argv'] : [];
$checkHostCli->check(
	$args[0],
	$args[1],
	empty($args[2]) ? null : (int)$args[2],
	in_array('--colors', $args, true),
	in_array('--strict', $args, true),
	in_array('--no-ipv6', $args, true),
);
