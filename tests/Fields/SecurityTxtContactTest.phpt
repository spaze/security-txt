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


	public function testEmail(): void
	{
		$uris = [];
		foreach (['security@example.com', "o'brien+tag@example.com", 'foo#bar@example.com', 'foo?bar@example.com', 'gorby%kremvax@example.com', '"not@me"@example.org', '"oh\\\\no"@example.org', '"a,b;c"@example.com', "security@h\u{E1}\u{10D}ky.example"] as $email) {
			$uris[$email] = SecurityTxtContact::email($email)->getUri();
		}
		Assert::same([
			'security@example.com' => 'mailto:security@example.com',
			"o'brien+tag@example.com" => "mailto:o'brien+tag@example.com",
			'foo#bar@example.com' => 'mailto:foo%23bar@example.com',
			'foo?bar@example.com' => 'mailto:foo%3Fbar@example.com',
			// Examples from RFC 6068
			'gorby%kremvax@example.com' => 'mailto:gorby%25kremvax@example.com',
			'"not@me"@example.org' => 'mailto:%22not%40me%22@example.org',
			'"oh\\\\no"@example.org' => 'mailto:%22oh%5C%5Cno%22@example.org',
			'"a,b;c"@example.com' => 'mailto:%22a%2Cb%3Bc%22@example.com',
			"security@h\u{E1}\u{10D}ky.example" => "mailto:security@h\u{E1}\u{10D}ky.example",
		], $uris);
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
