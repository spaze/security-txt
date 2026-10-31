<?php
/**
 * @testCase
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtFieldUriInWellKnown;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

final class UriCheckFieldValueInWellKnownTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setFileLocation('https://example.com/.well-known/security.txt');
		$warned = [];
		foreach (
			[
				'https://example.com/.well-known/policy.html',
				'https://example.com/.well-known/',
				'http://example.com/.well-known/policy.html',
				'https://example.com/.well-known/security.txt',
				'https://example.com/foo/../.well-known/policy.html',
				'/.well-known/policy.html',
				'/foo/../.well-known/policy.html',
				'<https://example.com/.well-known/policy.html>',
				'Policy: https://example.com/.well-known/policy.html',
				'https: //example.com/.well-known/policy.html',
				'HTTPS://EXAMPLE.COM/.well-known/policy.html',
				'https://example.com/policy.html',
				'https://example.com/.well-known',
				'https://example.com/.well-known-policy.html',
				'https://example.com/.WELL-KNOWN/policy.html',
				'https://example.com/foo/.well-known/policy.html',
				'https://example.com/?/.well-known/policy.html',
				'/.well-known/../policy.html',
				'.well-known/policy.html',
				'//example.com/.well-known/policy.html',
				'see /.well-known/policy.html',
				'ftp://example.com/.well-known/policy.html',
				'sip:/.well-known/security@example.com',
			] as $uri
		) {
			try {
				new UriCheckFieldValueInWellKnown(SecurityTxtField::Policy)->process($uri, $securityTxt);
				$warned[$uri] = false;
			} catch (SecurityTxtWarning $e) {
				Assert::type(SecurityTxtFieldUriInWellKnown::class, $e->getViolation());
				$warned[$uri] = true;
			}
		}
		Assert::same([
			'https://example.com/.well-known/policy.html' => true,
			'https://example.com/.well-known/' => true,
			'http://example.com/.well-known/policy.html' => true,
			'https://example.com/.well-known/security.txt' => true,
			'https://example.com/foo/../.well-known/policy.html' => true,
			'/.well-known/policy.html' => true,
			'/foo/../.well-known/policy.html' => true,
			'<https://example.com/.well-known/policy.html>' => true,
			'Policy: https://example.com/.well-known/policy.html' => true,
			'https: //example.com/.well-known/policy.html' => true,
			'HTTPS://EXAMPLE.COM/.well-known/policy.html' => true,
			'https://example.com/policy.html' => false,
			'https://example.com/.well-known' => false,
			'https://example.com/.well-known-policy.html' => false,
			'https://example.com/.WELL-KNOWN/policy.html' => false,
			'https://example.com/foo/.well-known/policy.html' => false,
			'https://example.com/?/.well-known/policy.html' => false,
			'/.well-known/../policy.html' => false,
			'.well-known/policy.html' => false,
			'//example.com/.well-known/policy.html' => false,
			'see /.well-known/policy.html' => false,
			'ftp://example.com/.well-known/policy.html' => false,
			'sip:/.well-known/security@example.com' => false,
		], $warned);
	}


	public function testProcessChecksTheSuggestedUri(): void
	{
		$withLocation = new SecurityTxt();
		$withLocation->setFileLocation('https://example.com/.well-known/security.txt');
		// A hostname gets a scheme only as a Contact, and a path gets the host only from the file location
		Assert::throws(function () use ($withLocation): void {
			new UriCheckFieldValueInWellKnown(SecurityTxtField::Contact)->process('example.com/.well-known/report', $withLocation);
		}, SecurityTxtWarning::class);
		Assert::noError(function () use ($withLocation): void {
			new UriCheckFieldValueInWellKnown(SecurityTxtField::Policy)->process('example.com/.well-known/report', $withLocation);
			new UriCheckFieldValueInWellKnown(SecurityTxtField::Policy)->process('/.well-known/policy.html', new SecurityTxt());
		});
	}


	public function testMessage(): void
	{
		$e = Assert::throws(function (): void {
			new UriCheckFieldValueInWellKnown(SecurityTxtField::Encryption)->process('https://example.com/.well-known/key.asc', new SecurityTxt());
		}, SecurityTxtWarning::class);
		assert($e instanceof SecurityTxtWarning);
		$violation = $e->getViolation();
		Assert::same('The Encryption value (https://example.com/.well-known/key.asc) points under the /.well-known/ path, where only the names registered with IANA can be used', $violation->getMessage());
		Assert::same('Move it out of the /.well-known/ path, unless the name it uses there is in the Well-Known URIs registry at IANA', $violation->getHowToFix());
		Assert::null($violation->getCorrectValue());
	}

}

new UriCheckFieldValueInWellKnownTest()->run();
