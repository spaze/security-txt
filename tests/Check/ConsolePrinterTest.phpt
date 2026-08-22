<?php
/** @noinspection HttpUrlsUsage */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class ConsolePrinterTest extends TestCase
{

	public function testPrinterColorsOn(): void
	{
		$printer = new ConsolePrinter();
		$printer->enableColors();
		ob_start();
		$printer->ok('dancer');
		$printer->info('Never');
		$printer->error('gonna');
		$printer->warning('give');
		$printer->info($printer->colorGreen('you'));
		$printer->info($printer->colorBold('up'));
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;32m[OK][0m dancer
		[1;90m[Info][0m Never
		[1;31m[Error][0m gonna
		[1m[Warning][0m give
		[1;90m[Info][0m [1;32myou[0m
		[1;90m[Info][0m [1mup[0m
		EOT;
		Assert::same($expected . "\n", $output);
	}


	public function testPrinterColorsOff(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		$printer->ok('dancer');
		$printer->info('Never');
		$printer->error('gonna');
		$printer->warning('give');
		$printer->info($printer->colorGreen('you'));
		$printer->info($printer->colorBold('up'));
		$output = ob_get_clean();
		$expected = <<< EOT
		[OK] dancer
		[Info] Never
		[Error] gonna
		[Warning] give
		[Info] you
		[Info] up
		EOT;
		Assert::same($expected . "\n", $output);
	}


	public function testPrinterRemovesWhatAHostCouldRedrawTheOutputWith(): void
	{
		$printer = new ConsolePrinter();
		$printer->enableColors();
		ob_start();
		// Erase line, then a colour, then a bidi override, C1 as UTF-8 and as a bare byte, and a zero width space that hides a letter
		$printer->info('Redirected to ' . $printer->colorBold("https://evi\u{200B}l.example/\x1b[2K\u{202E}x\u{9B}y\x9bz"));
		$output = ob_get_clean();
		Assert::same("\x1b[1;90m[Info]\x1b[0m Redirected to \x1b[1mhttps://evil.example/[2Kxyz\x1b[0m\n", $output);
	}


	public function testPrinterKeepsTheArrowItPrintsItself(): void
	{
		$printer = new ConsolePrinter();
		ob_start();
		$printer->error('a → b → c');
		$output = ob_get_clean();
		Assert::same("[Error] a → b → c\n", $output);
	}

}

(new ConsolePrinterTest())->run();
