<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class ContactTest extends TestCase
{

	/**
	 * @noinspection HttpUrlsUsage
	 * @noinspection PhpExpressionResultUnusedInspection
	 */
	public function testValues(): void
	{
		Assert::noError(function (): void {
			new Contact('https://example.com/contact');
			new Contact('http://example.com/contact');
			new Contact('mailto:foo@example.com');
			new Contact('foo@example.com');
			new Contact('tel:+1-201-555-0123');
		});
	}

}

(new ContactTest())->run();
