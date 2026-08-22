<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/**
 * The format lists one placeholder per canonical URI and the values have to match it, so the message is built here with none, one and two of them.
 *
 * @testCase
 */
final class SecurityTxtCanonicalUriMismatchTest extends TestCase
{

	public function testGetMessage(): void
	{
		// The validator always has at least one, an empty list arrives from the public constructor or from serialized JSON, and gets a sentence rather than empty brackets
		Assert::same(
			'The file was fetched from https://1.example/ but lists no Canonical field at all',
			new SecurityTxtCanonicalUriMismatch('https://1.example/', [])->getMessage(),
		);
		Assert::same(
			'Add a new Canonical field with the URI https://1.example/',
			new SecurityTxtCanonicalUriMismatch('https://1.example/', [])->getHowToFix(),
		);
		Assert::same(
			'The file was fetched from https://1.example/ but the Canonical field (https://2.example/) does not list this URI',
			new SecurityTxtCanonicalUriMismatch('https://1.example/', ['https://2.example/'])->getMessage(),
		);
		Assert::same(
			'The file was fetched from https://1.example/ but none of the Canonical fields (https://2.example/, https://3.example/) list this URI',
			new SecurityTxtCanonicalUriMismatch('https://1.example/', ['https://2.example/', 'https://3.example/'])->getMessage(),
		);
	}

}

new SecurityTxtCanonicalUriMismatchTest()->run();
