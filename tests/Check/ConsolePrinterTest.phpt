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

	private ConsolePrinter $printer;


	public function __construct()
	{
		$this->printer = new ConsolePrinter();
	}


	public function testPrinter(): void
	{
		$this->printer->enableColors();
		ob_start();
		$this->printer->info('Never');
		$this->printer->error('gonna');
		$this->printer->warning('give');
		$this->printer->info($this->printer->colorGreen('you'));
		$this->printer->info($this->printer->colorBold('up'));
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;90m[Info][0m Never
		[1;31m[Error][0m gonna
		[1m[Warning][0m give
		[1;90m[Info][0m [1;32myou[0m
		[1;90m[Info][0m [1mup[0m
		EOT;
		Assert::same($expected . "\n", $output);
	}


	public function testPrinterRemovesWhatAHostCouldRedrawTheOutputWith(): void
	{
		$this->printer->enableColors();
		ob_start();
		// Erase line, then a colour, then a bidi override, C1 as UTF-8 and as a bare byte, and a zero width space hiding a letter of the name
		$this->printer->info('Redirected to ' . $this->printer->colorBold("https://evi\u{200B}l.example/\x1b[2K\u{202E}x\u{9B}y\x9bz"));
		$output = ob_get_clean();
		// Encoded rather than dropped, so the report still says what arrived: the zero width space hiding a letter of the name is visible as %E2%80%8B
		Assert::same("\x1b[1;90m[Info]\x1b[0m Redirected to \x1b[1mhttps://evi%E2%80%8Bl.example/%1B[2K%E2%80%AEx%C2%9By%9Bz\x1b[0m\n", $output);
	}


	public function testPrinterRemovesEvenItsOwnColorsWhenColorsAreOff(): void
	{
		$this->printer = new ConsolePrinter();
		ob_start();
		$this->printer->info("host sent \x1b[1;32mgreen\x1b[0m");
		$output = ob_get_clean();
		Assert::same("[Info] host sent %1B[1;32mgreen%1B[0m\n", $output);
	}


	public function testPrinterKeepsTheArrowItPrintsItself(): void
	{
		$this->printer = new ConsolePrinter();
		ob_start();
		$this->printer->error('a → b → c');
		$output = ob_get_clean();
		Assert::same("[Error] a → b → c\n", $output);
	}

}

(new ConsolePrinterTest())->run();
