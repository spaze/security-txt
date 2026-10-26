<?php
/**
 * @testCase
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

final class SecurityTxtContactTest extends TestCase
{

	/**
	 * @return list<list<string>>
	 * @noinspection HttpUrlsUsage
	 */
	public function getUris(): array
	{
		return [
			['https://example.com/contact'],
			['http://example.com/contact'],
			['mailto:foo@example.com'],
			['foo@example.com'],
			['tel:+1-201-555-0123'],
		];
	}


	/**
	 * @dataProvider getUris
	 */
	public function testValues(string $uri): void
	{
		Assert::noError(function () use ($uri): void {
			Assert::same($uri, (new SecurityTxtContact($uri))->getUri());
		});
	}


	public function testPhone(): void
	{
		$uris = [];
		foreach (['+420 123 456 789', '+1-201-555-0123', '123456'] as $phone) {
			$uris[$phone] = SecurityTxtContact::phone($phone)->getUri();
		}
		Assert::same([
			'+420 123 456 789' => 'tel:+420-123-456-789',
			'+1-201-555-0123' => 'tel:+1-201-555-0123',
			'123456' => 'tel:123456',
		], $uris);
	}

}

(new SecurityTxtContactTest())->run();
