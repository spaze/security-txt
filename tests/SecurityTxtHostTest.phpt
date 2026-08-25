<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/bootstrap.php';

/** @testCase */
final class SecurityTxtHostTest extends TestCase
{

	public function testFromStringAcceptsOnlyTheSerializedForm(): void
	{
		$host = SecurityTxtHost::fromString('bücher.example');
		Assert::same('bücher.example', $host->getUnicode());
		Assert::same('xn--bcher-kva.example', $host->getAscii());
		$host = SecurityTxtHost::fromString('example.com');
		Assert::same('example.com', $host->getUnicode());
		Assert::same('example.com', $host->getAscii());
	}


	public function testFromStringRefusesWhatWouldBeSilentlyRewritten(): void
	{
		// Would read back as the IP address 0.0.3.40
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('808');
		}, SecurityTxtCannotParseHostnameException::class);
		// A valid spelling of a host, but not one getUnicode() ever writes, would read back as bücher.example
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('xn--bcher-kva.example');
		}, SecurityTxtCannotParseHostnameException::class);
		// Would read back lowercased
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('Example.COM');
		}, SecurityTxtCannotParseHostnameException::class);
		// A URL, not a host, would read back without the path
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('https://example.com/');
		}, SecurityTxtCannotParseHostnameException::class);
		Assert::throws(function (): void {
			SecurityTxtHost::fromString('not a hostname');
		}, SecurityTxtCannotParseHostnameException::class);
	}


	public function testAnOpaqueHostIsKeptAsWhateverParsingMadeOfIt(): void
	{
		// A scheme WhatWG calls special, ftp among them, runs IDNA like https does, so those hosts round trip; one it calls opaque does not run IDNA and keeps its case,
		// which is why such a host cannot be rebuilt from what `getUnicode()` writes and `fromString()` refuses it rather than quietly returning a different host
		$fromFtp = new SecurityTxtHost(new Url('ftp://bücher.example'));
		Assert::same('bücher.example', $fromFtp->getUnicode());
		Assert::same('xn--bcher-kva.example', $fromFtp->getAscii());
		$opaque = new SecurityTxtHost(new Url('foo://Plain.Example/x'));
		Assert::same('plain.example', $opaque->getUnicode());
		Assert::same('Plain.Example', $opaque->getAscii());
		Assert::throws(function () use ($opaque): void {
			SecurityTxtHost::fromString($opaque->getAscii());
		}, SecurityTxtCannotParseHostnameException::class);
	}

}

(new SecurityTxtHostTest())->run();
