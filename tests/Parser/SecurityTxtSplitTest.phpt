<?php
/**
 * @testCase
 * @noinspection PhpFullyQualifiedNameUsageInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use LogicException;
use Override;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtSplitProvider;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

final class SecurityTxtSplitLinesTest extends TestCase
{

	private SecurityTxtSplitLines $securityTxtSplitLines;


	public function __construct()
	{
		$provider = new class implements SecurityTxtSplitProvider
		{

			#[Override]
			public function split(string $pattern, string $subject, bool $noEmpty = false): array|false
			{
				return false;
			}

		};
		$this->securityTxtSplitLines = new SecurityTxtSplitLines($provider);
	}


	public function testSplitLines(): void
	{
		$lines = new SecurityTxtSplitLines(new SecurityTxtPregSplitProvider())->splitLines("a\nb\r\nc\rd\r\r\ne");
		Assert::same(["a\n", "b\r\n", "c\r", "d\r", "\r\n", 'e'], $lines);
	}


	public function testSplitLinesPregSplitFailure(): void
	{
		Assert::throws(function (): void {
			$this->securityTxtSplitLines->splitLines('');
		}, LogicException::class, 'This should not happen');
	}

}

(new SecurityTxtSplitLinesTest())->run();
