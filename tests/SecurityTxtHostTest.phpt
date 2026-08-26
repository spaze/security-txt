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


	public function testBothSpellingsOfAHostAskForTheSameName(): void
	{
		// Whichever way a host was written, the ASCII form is what goes to the resolver and onto the wire, so both spellings have to arrive at the same one
		$readable = new SecurityTxtHost(new Url("https://h\u{E1}\u{10D}ky\u{10D}\u{E1}rky.cz/"));
		$punycode = new SecurityTxtHost(new Url('https://xn--hkyrky-ptac70bc.cz/'));
		Assert::same('xn--hkyrky-ptac70bc.cz', $readable->getAscii());
		Assert::same($readable->getAscii(), $punycode->getAscii());
		Assert::same($readable->getUnicode(), $punycode->getUnicode());
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
