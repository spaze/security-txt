<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtAcknowledgmentsNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtAcknowledgmentsNotUriSyntaxError;
use Spaze\SecurityTxt\Fields\Acknowledgments;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
class AcknowledgmentsAddFieldValueTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new AcknowledgmentsAddFieldValue();

		$uri1 = 'https://ack.ack.example/';
		$uri2 = 'https://ack.example.com/';
		$uri3 = 'telnet://wat';
		$processor->process($uri1, $securityTxt);
		$processor->process($uri2, $securityTxt);
		$processor->process($uri3, $securityTxt);
		$actual = array_map(fn(Acknowledgments $field): string => $field->getUri(), $securityTxt->getAcknowledgments());
		Assert::equal([$uri1, $uri2, $uri3], $actual);

		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('http://no.https.example', $securityTxt);
		}, SecurityTxtAcknowledgmentsNotHttpsError::class);

		Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('no.scheme', $securityTxt);
		}, SecurityTxtAcknowledgmentsNotUriSyntaxError::class);
	}

}

(new AcknowledgmentsAddFieldValueTest())->run();