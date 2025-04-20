<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtPreferredLanguagesTest extends TestCase
{

	/**
	 * @return list<list<list<string>>>
	 */
	public function getLanguages(): array
	{
		return [
			[[]],
			[['en']],
			[['en', 'cs']],
			[['en', 'cz']],
			[['303']],
		];
	}


	/**
	 * @param list<string> $languages
	 * @dataProvider getLanguages
	 */
	public function testValues(array $languages): void
	{
		Assert::noError(function () use ($languages): void {
			Assert::same($languages, new SecurityTxtPreferredLanguages($languages)->getLanguages());
		});
	}

}

new SecurityTxtPreferredLanguagesTest()->run();
