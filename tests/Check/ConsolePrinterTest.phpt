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

}

(new ConsolePrinterTest())->run();
