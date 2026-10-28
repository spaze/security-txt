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
use Uri\WhatWg\Url;

require __DIR__ . '/../bootstrap.php';

/**
 * A violation says where in the spec it comes from as well as what is wrong, and a consumer renders that, turning `getSpecSection()` into a link to the section of RFC
 * 9116 it names. Nothing inside this library reads any of it, the serialized form stopped carrying it once the decoder was shown to recompute everything from the
 * constructor arguments, so without this they would be exercised by nothing at all.
 */
final class SecurityTxtSpecViolationTest extends TestCase
{

	public function testWhereInTheSpecAViolationComesFrom(): void
	{
		$lineNoEol = new SecurityTxtLineNoEol('Contact: https://example.com/');
		Assert::same('draft-foudil-securitytxt-03', $lineNoEol->getSince());
		Assert::same('2.2', $lineNoEol->getSpecSection());
		Assert::same(['4'], $lineNoEol->getSeeAlsoSections());
		Assert::null($lineNoEol->getSpecUrl());

		// A field the RFC does not define points somewhere other than the RFC, which is the case the nullable `specUrl` exists for
		$bugBounty = new SecurityTxtBugBountyWrongCase('false');
		Assert::same('https://www.iana.org/assignments/security-txt-fields/security-txt-fields.xhtml#security-txt-fields', $bugBounty->getSpecUrl());
		Assert::same([], $bugBounty->getSeeAlsoSections());

		// A violation can point at more than one section, which is what `getSeeAlsoSections()` carries beside the one it is filed under
		$noContact = new SecurityTxtNoContact();
		Assert::same('2.5.3', $noContact->getSpecSection());
		Assert::same(['2.5.4'], $noContact->getSeeAlsoSections());
	}


	public function testWording(): void
	{
		$url = new Url('https://example.com/.well-known/security.txt');
		$violations = [
			'LineNoEol' => new SecurityTxtLineNoEol('Contact: https://example.com/'),
			'ContentTypeInvalid' => new SecurityTxtContentTypeInvalid($url, 'text/html'),
			'ContentTypeInvalid none' => new SecurityTxtContentTypeInvalid($url, null),
			'ExpiresSoon 1' => new SecurityTxtExpiresSoon(1),
			'ExpiresSoon 0' => new SecurityTxtExpiresSoon(0),
			'SeparatorNotComma' => new SecurityTxtPreferredLanguagesSeparatorNotComma([2 => ';'], ['en', 'cs']),
			'WrongLanguageTags' => new SecurityTxtPreferredLanguagesWrongLanguageTags([2 => 'english']),
			'CommonMistake' => new SecurityTxtPreferredLanguagesCommonMistake(2, 'cz', 'cs', SecurityTxtPreferredLanguagesCommonMistakeReason::CzechUsesCsNotCz),
			'SignedButNoCanonical' => new SecurityTxtSignedButNoCanonical(),
			'TopLevelDiffers' => new SecurityTxtTopLevelDiffers('a', 'b'),
			'WellKnownPathOnly' => new SecurityTxtWellKnownPathOnly(),
			'ExpiresOldFormat' => new SecurityTxtExpiresOldFormat('2027-01-31T23:59:59+00:00'),
		];
		$actual = array_map(fn(SecurityTxtSpecViolation $violation): array => [$violation->getMessage(), $violation->getHowToFix()], $violations);
		Assert::same([
			'LineNoEol' => ["The line (Contact: https://example.com/) doesn't end with either <CRLF> or <LF>", 'End the line with either <CRLF> or <LF>'],
			'ContentTypeInvalid' => ['The file at https://example.com/.well-known/security.txt has a Content-Type of text/html but it should be a Content-Type of text/plain with the charset parameter set to utf-8', 'Send a correct Content-Type header value of text/plain with the charset parameter set to utf-8'],
			'ContentTypeInvalid none' => ['The file at https://example.com/.well-known/security.txt has no Content-Type but it should be a Content-Type of text/plain with the charset parameter set to utf-8', 'Send a correct Content-Type header value of text/plain with the charset parameter set to utf-8'],
			'ExpiresSoon 1' => ['The file will be considered stale in 1 day', 'Update the value of the Expires field'],
			'ExpiresSoon 0' => ['The file will be considered stale in less than a day', 'Update the value of the Expires field'],
			'SeparatorNotComma' => ['The Preferred-Languages field uses a wrong separator (#2 ;), separate multiple values with a comma (,)', 'Use a comma (,) to list multiple languages in the Preferred-Languages field'],
			'WrongLanguageTags' => ['The language tag #2 english seems invalid, the Preferred-Languages field must contain one or more language tags as defined in RFC 5646', 'Use language tags as defined in RFC 5646, which usually means the shortest ISO 639 code, for example en'],
			'CommonMistake' => ['The language tag #2 cz in the Preferred-Languages field is not correct, the code for the Czech language is cs', 'Use language tags as defined in RFC 5646, which usually means the shortest ISO 639 code'],
			'SignedButNoCanonical' => ['When digital signatures are used, it is also recommended that organizations use the Canonical field', 'Add a Canonical field with the URI where the security.txt file is located'],
			'TopLevelDiffers' => ['The file at the top-level path is different from the one in the /.well-known/ path', 'Redirect the top-level file to the one under the /.well-known/ path'],
			'WellKnownPathOnly' => ["security.txt wasn't found at the top-level path", 'Redirect the top-level file to the one under the /.well-known/ path'],
			'ExpiresOldFormat' => ['The value of the Expires field follows the format defined in Section 3.3 of RFC 5322 but it should be formatted according to the Internet profile of ISO 8601 as defined in RFC 3339', 'Change the value of the Expires field to use the correct format'],
		], $actual);
	}

}

new SecurityTxtSpecViolationTest()->run();
