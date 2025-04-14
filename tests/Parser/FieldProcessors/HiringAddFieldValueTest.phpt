<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\Hiring;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotUri;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class HiringAddFieldValueTest extends TestCase
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

		$e = Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('http://no.https.example', $securityTxt);
		}, SecurityTxtError::class);
		Assert::type(SecurityTxtHiringNotHttps::class, $e->getViolation());

		$e = Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('no.scheme', $securityTxt);
		}, SecurityTxtError::class);
		Assert::type(SecurityTxtHiringNotUri::class, $e->getViolation());
	}

}

new HiringAddFieldValueTest()->run();
