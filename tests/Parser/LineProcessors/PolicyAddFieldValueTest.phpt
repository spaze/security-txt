<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtPolicyNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPolicyNotUriSyntaxError;
use Spaze\SecurityTxt\Fields\Policy;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
class PolicyAddFieldValueTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new PolicyAddFieldValue();

		$uri1 = 'https://pol.icy.example/';
		$uri2 = 'https://policy.example.com/';
		$uri3 = 'pop3://wat';
		$processor->process($uri1, $securityTxt);
		$processor->process($uri2, $securityTxt);
		$processor->process($uri3, $securityTxt);
		$actual = array_map(fn(Policy $field): string => $field->getUri(), $securityTxt->getPolicy());
		Assert::equal([$uri1, $uri2, $uri3], $actual);

		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('http://no.https.example', $securityTxt);
		}, SecurityTxtPolicyNotHttpsError::class);

		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('no.scheme', $securityTxt);
		}, SecurityTxtPolicyNotUriSyntaxError::class);
	}

}

(new PolicyAddFieldValueTest())->run();
