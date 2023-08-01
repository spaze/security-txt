<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtHiringNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtHiringNotUriSyntaxError;
use Spaze\SecurityTxt\Fields\Hiring;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
class HiringAddFieldValueTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new HiringAddFieldValue();

		$uri1 = 'https://hi.hi.example/';
		$uri2 = 'https://hi.example.com/';
		$uri3 = 'smtp://wat';
		$processor->process($uri1, $securityTxt);
		$processor->process($uri2, $securityTxt);
		$processor->process($uri3, $securityTxt);
		$actual = array_map(fn(Hiring $field): string => $field->getUri(), $securityTxt->getHiring());
		Assert::equal([$uri1, $uri2, $uri3], $actual);

		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('http://no.https.example', $securityTxt);
		}, SecurityTxtHiringNotHttpsError::class);

		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('no.scheme', $securityTxt);
		}, SecurityTxtHiringNotUriSyntaxError::class);
	}

}

(new HiringAddFieldValueTest())->run();
