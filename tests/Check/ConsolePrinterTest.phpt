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
		$printer->ok('🕺');
		$printer->info('Never');
		$printer->error('gonna');
		$printer->warning('give');
		$printer->info($printer->colorGreen('you'));
		$printer->info($printer->colorBold('up'));
		$output = ob_get_clean();
		$expected = <<< EOT
		[1;32m[OK][0m 🕺
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
		$printer->ok('🕺');
		$printer->info('Never');
		$printer->error('gonna');
		$printer->warning('give');
		$printer->info($printer->colorGreen('you'));
		$printer->info($printer->colorBold('up'));
		$output = ob_get_clean();
		$expected = <<< EOT
		[OK] 🕺
		[Info] Never
		[Error] gonna
		[Warning] give
		[Info] you
		[Info] up
		EOT;
		Assert::same($expected . "\n", $output);
	}

}

(new ConsolePrinterTest())->run();
