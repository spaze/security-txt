<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use LogicException;
use Override;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtSplitProvider;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class PreferredLanguagesSetFieldValueTest extends TestCase
{

	public function testProcessPregSplitFailure(): void
	{
		$securityTxt = new SecurityTxt();
		$splitProvider = new class implements SecurityTxtSplitProvider
		{

			#[Override]
			public function split(string $pattern, string $subject, bool $noEmpty = false): array|false
			{
				return false;
			}

		};
		$processor = new PreferredLanguagesSetFieldValue($splitProvider);
		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process("", $securityTxt);
		}, LogicException::class, 'This should not happen');
	}

}

(new PreferredLanguagesSetFieldValueTest())->run();
