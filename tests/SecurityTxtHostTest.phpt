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
		Assert::true($host->isInternationalized());
		$host = SecurityTxtHost::fromString('example.com');
		Assert::same('example.com', $host->getUnicode());
		Assert::false($host->isInternationalized());
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


	public function testSchemeDoesNotChangeWhatFromStringRebuilds(): void
	{
		// The scheme decides whether IDNA ran, so a host built from an ftp URL judged under ftp would flip once it lived through getUnicode() and fromString()
		$fromFtp = new SecurityTxtHost(new Url('ftp://bücher.example')->withScheme('https'));
		$roundTripped = SecurityTxtHost::fromString($fromFtp->getUnicode());
		Assert::same($fromFtp->isInternationalized(), $roundTripped->isInternationalized());
		Assert::same($fromFtp->getAscii(), $roundTripped->getAscii());
	}

}

(new SecurityTxtHostTest())->run();
