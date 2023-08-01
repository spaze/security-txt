<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtEncryptionNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtEncryptionNotUriSyntaxError;
use Spaze\SecurityTxt\Fields\Encryption;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
class EncryptionAddFieldValueTest extends TestCase
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

		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('http://no.https.example', $securityTxt);
		}, SecurityTxtEncryptionNotHttpsError::class);

		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('no.scheme', $securityTxt);
		}, SecurityTxtEncryptionNotUriSyntaxError::class);
	}

}

(new EncryptionAddFieldValueTest())->run();
