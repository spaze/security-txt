#!/usr/bin/env php
<?php
declare(strict_types = 1);

use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;

require_once __DIR__ . '/../vendor/autoload.php';

if (!isset($_SERVER['argv'][1])) {
	echo 'Usage: ' . $_SERVER['argv'][0] . " <file> [days]\nThe check will return 1 instead of 0 if the file has expired or expires in less than [days]\n";
	exit(2);
}

$red = "\033[1;31m";
$green = "\033[1;32m";
$bold = "\033[1m";
$clear = "\033[0m";

$contents = file_get_contents($_SERVER['argv'][1]);
if ($contents === false) {
	exit(3);
}

$validator = new SecurityTxtValidator();
$parser = new SecurityTxtParser($validator);
$parseResult = $parser->parseString($contents);

foreach ($parseResult->getParseErrors() as $line => $errors) {
	foreach ($errors as $error) {
		echo "[{$red}Error{$clear}] on line {$bold}$line{$clear}: " . $error->getMessage() . "\n";
	}
}
foreach ($parseResult->getFileErrors() as $error) {
	echo "[{$red}Error{$clear}]: " . $error->getMessage() . "\n";
}
foreach ($parseResult->getParseWarnings() as $line => $warnings) {
	foreach ($warnings as $warning) {
		echo "[{$bold}Warning{$clear}] on line {$bold}$line{$clear}: " . $warning->getMessage() . "\n";
	}
}

$expires = $parseResult->getSecurityTxt()->getExpires();
if ($expires !== null) {
	$days = $expires->inDays();
	$expiresDate = $expires->getDateTime()->format(DATE_RFC3339);
	if ($expires->isExpired()) {
		printf("{$red}The file has expired %s %s ago{$clear} (%s)\n", abs($days), $days === 1 ? 'day' : 'days', $expiresDate);
	} else {
		printf("{$green}The file will expire in %s %s{$clear} (%s)\n", $days, $days === 1 ? 'day' : 'days', $expiresDate);
	}
	if ($expires->isExpired() || isset($_SERVER['argv'][2]) && $days < $_SERVER['argv'][2]) {
		echo "{$red}Please update the file!{$clear}\n";
		exit(1);
	}
}
exit(0);
