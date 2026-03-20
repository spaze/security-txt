<?php
/** @noinspection PhpFullyQualifiedNameUsageInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use LogicException;
use Override;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtSplitProvider;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
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


	public function testSplitLinesPregSplitFailure(): void
	{
		Assert::throws(function (): void {
			$this->securityTxtSplitLines->splitLines('');
		}, LogicException::class, 'This should not happen');
	}

}

(new SecurityTxtSplitLinesTest())->run();
