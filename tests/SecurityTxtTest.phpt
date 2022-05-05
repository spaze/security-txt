<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtCanonicalNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresTooLongWarning;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\Fields\Expires;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/bootstrap.php';

/** @testCase */
class SecurityTxtTest extends TestCase
{

	public function testSetExpires(): void
	{
		$securityTxt = new SecurityTxt();
		$in2Weeks = new Expires(new DateTimeImmutable('+2 weeks'));
		$in3Weeks = new Expires(new DateTimeImmutable('+3 weeks'));
		$securityTxt->setExpires($in2Weeks);
		$securityTxt->setExpires($in3Weeks);
		Assert::equal($in3Weeks, $securityTxt->getExpires());
	}


	public function testSetExpiresTooLong(): void
	{
		$securityTxt = new SecurityTxt();
		$future = new Expires(new DateTimeImmutable('+1 year +1 month'));
		Assert::throws(function () use ($securityTxt, $future): void {
			$securityTxt->setExpires($future);
		}, SecurityTxtExpiresTooLongWarning::class);
		Assert::equal($future, $securityTxt->getExpires());
	}


	public function testSetCanonical(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->addCanonical(new Canonical('ftp://foo.bar.example.net/security.txt'));
		Assert::throws(function () use ($securityTxt): void {
			$securityTxt->addCanonical(new Canonical('http://example.com/.well-known/security.txt'));
		}, SecurityTxtCanonicalNotHttpsError::class);
		$securityTxt->addCanonical(new Canonical('https://example.com/.well-known/security.txt'));
		$securityTxt->addCanonical(new Canonical('C:\\security.txt'));
		Assert::same(
			[
				'ftp://foo.bar.example.net/security.txt',
				'https://example.com/.well-known/security.txt',
				'C:\\security.txt',
			],
			array_map(function (Canonical $canonical): string {
				return $canonical->getUri();
			}, $securityTxt->getCanonical()),
		);
	}


	public function testSetCanonicalWithInvalidValues(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->allowFieldsWithInvalidValues();
		$url = 'http://example.com/.well-known/security.txt';
		Assert::throws(function () use ($securityTxt, $url): void {
			$securityTxt->addCanonical(new Canonical($url));
		}, SecurityTxtCanonicalNotHttpsError::class);
		Assert::equal([new Canonical($url)], $securityTxt->getCanonical());
	}

}

(new SecurityTxtTest())->run();
