#!/usr/bin/env php
<?php
declare(strict_types = 1);

use Spaze\SecurityTxt\Check\SecurityTxtCheckFile;
use Spaze\SecurityTxt\Parser\SecurityTxtParser;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;

require_once __DIR__ . '/../vendor/autoload.php';

$validator = new SecurityTxtValidator();
$parser = new SecurityTxtParser($validator);
$checkFile = new SecurityTxtCheckFile($parser, $_SERVER['argv'][0]);
$checkFile->check($_SERVER['argv'][1] ?? null, isset($_SERVER['argv'][2]) ? (int)$_SERVER['argv'][2] : null);
