<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\Encryption;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtEncryptionNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtEncryptionNotUri;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class EncryptionAddFieldValueTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new EncryptionAddFieldValue();

		$uri1 = 'https://no.keys.example/';
		$uri2 = 'https://keys.example.com/';
		$uri3 = 'blob://rly';
		$processor->process($uri1, $securityTxt);
		$processor->process($uri2, $securityTxt);
		$processor->process($uri3, $securityTxt);
		$actual = array_map(fn(Encryption $field): string => $field->getUri(), $securityTxt->getEncryption());
		Assert::equal([$uri1, $uri2, $uri3], $actual);

		$e = Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('http://no.https.example', $securityTxt);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtEncryptionNotHttps::class, $e->getViolation());

		$e = Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('no.scheme', $securityTxt);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtEncryptionNotUri::class, $e->getViolation());
	}

}

new EncryptionAddFieldValueTest()->run();
