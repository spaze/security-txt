<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/**
 * A violation says where in the spec it comes from as well as what is wrong, and a consumer renders that, turning `getSpecSection()` into a link to the section of RFC
 * 9116 it names. Nothing inside this library reads any of it, the serialized form stopped carrying it once the decoder was shown to recompute everything from the
 * constructor arguments, so without this they would be exercised by nothing at all.
 *
 * @testCase
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

}

new SecurityTxtSpecViolationTest()->run();
