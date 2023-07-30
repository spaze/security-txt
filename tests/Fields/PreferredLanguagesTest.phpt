<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class PreferredLanguagesTest extends TestCase
{

	/**
	 * @noinspection PhpExpressionResultUnusedInspection
	 */
	public function testValues(): void
	{
		Assert::noError(function (): void {
			new PreferredLanguages([]);
			new PreferredLanguages(['en']);
			new PreferredLanguages(['en', 'cs']);
			new PreferredLanguages(['en', 'cz']);
			new PreferredLanguages(['303']);
		});
	}

}

(new PreferredLanguagesTest())->run();
