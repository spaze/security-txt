<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/**
 * The format lists one placeholder per canonical URI and the values have to match it, so the message is built here with none, one and two of them.
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
			"The file was fetched from https://1.example/ but the Canonical field (https://2.example/) doesn't list this URI, so the contents of the file shouldn't be trusted",
			new SecurityTxtCanonicalUriMismatch('https://1.example/', ['https://2.example/'])->getMessage(),
		);
		Assert::same(
			"The file was fetched from https://1.example/ but none of the Canonical fields (https://2.example/, https://3.example/) list this URI, so the contents of the file shouldn't be trusted",
			new SecurityTxtCanonicalUriMismatch('https://1.example/', ['https://2.example/', 'https://3.example/'])->getMessage(),
		);
	}


	public function testGetHowToFix(): void
	{
		$wellKnown = 'https://example.com/.well-known/security.txt';
		$violations = [
			'unspecified' => new SecurityTxtCanonicalUriMismatch($wellKnown, ['https://other.example/.well-known/security.txt']),
			'same host' => new SecurityTxtCanonicalUriMismatch($wellKnown, ['https://example.com/.well-known/sercurity.txt'], SecurityTxtCanonicalUriMismatchReason::SameHost),
			'same host of two' => new SecurityTxtCanonicalUriMismatch($wellKnown, ['https://other.example/', 'https://example.com/.well-known/sercurity.txt'], SecurityTxtCanonicalUriMismatchReason::SameHost),
			'top-level listed' => new SecurityTxtCanonicalUriMismatch($wellKnown, ['https://example.com/security.txt'], SecurityTxtCanonicalUriMismatchReason::TopLevelListed),
			'well-known listed' => new SecurityTxtCanonicalUriMismatch('https://example.com/security.txt', [$wellKnown], SecurityTxtCanonicalUriMismatchReason::WellKnownListed),
		];
		Assert::same([
			'unspecified' => ['Add a new Canonical field with the URI https://example.com/.well-known/security.txt, or ensure the file is fetched from the listed canonical URI', []],
			'same host' => ['Change the Canonical field to https://example.com/.well-known/security.txt, the URI the file was fetched from', []],
			'same host of two' => ['Change the Canonical field naming this host to https://example.com/.well-known/security.txt, the URI the file was fetched from', []],
			'top-level listed' => ['Add a new Canonical field with the URI https://example.com/.well-known/security.txt, as the file under the /.well-known/ path is the one used', ['3']],
			'well-known listed' => ['Serve the file under the /.well-known/ path, which the Canonical field lists, and redirect /security.txt to /.well-known/security.txt', ['3']],
		], array_map(fn(SecurityTxtCanonicalUriMismatch $violation): array => [$violation->getHowToFix(), $violation->getSeeAlsoSections()], $violations));
	}

}

new SecurityTxtCanonicalUriMismatchTest()->run();
