<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtCanonicalNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
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


	/**
	 * @return array<string, array{0: array<string, class-string<SecurityTxtError>|null>, 1: class-string, 2: callable(SecurityTxt):callable, 3: callable(SecurityTxt):callable, 4: callable}>
	 * @noinspection HttpUrlsUsage
	 */
	public function getAddFieldValues(): array
	{
		return [
			'canonical' => [
				[
					'https://example.com/.well-known/security.txt' => null,
					'http://example.com/.well-known/security.txt' => SecurityTxtCanonicalNotHttpsError::class,
					'ftp://foo.bar.example.net/security.txt' => null,
					'C:\\security.txt' => null,
				],
				Canonical::class,
				function (SecurityTxt $securityTxt): callable {
					return $securityTxt->addCanonical(...);
				},
				function (SecurityTxt $securityTxt): callable {
					return $securityTxt->getCanonical(...);
				},
				function (Canonical $canonical): string {
					return $canonical->getUri();
				},
			],
		];
	}


	/**
	 * @param array<string, class-string<SecurityTxtError>|null> $values
	 * @param class-string $fieldClass
	 * @param callable(SecurityTxt): callable $addFactory
	 * @param callable(SecurityTxt): callable $getFieldFactory
	 * @param callable $getValue
	 * @dataProvider getAddFieldValues
	 */
	public function testAddField(array $values, string $fieldClass, callable $addFactory, callable $getFieldFactory, callable $getValue): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxtWithInvalidValues = new SecurityTxt();
		$securityTxtWithInvalidValues->allowFieldsWithInvalidValues();
		$allValues = $validValues = [];

		foreach ($values as $value => $exception) {
			$allValues[] = $value;
			if ($exception) {
				Assert::throws(function () use ($securityTxt, $value, $fieldClass, $addFactory): void {
					$addFactory($securityTxt)(new $fieldClass($value));
				}, $exception);
				Assert::throws(function () use ($securityTxtWithInvalidValues, $value, $fieldClass, $addFactory): void {
					$addFactory($securityTxtWithInvalidValues)(new $fieldClass($value));
				}, $exception);
			} else {
				$validValues[] = $value;
				$addFactory($securityTxt)(new $fieldClass($value));
				$addFactory($securityTxtWithInvalidValues)(new $fieldClass($value));
			}
		}

		Assert::same($validValues, array_map($getValue, $getFieldFactory($securityTxt)()));
		Assert::same($allValues, array_map($getValue, $getFieldFactory($securityTxtWithInvalidValues)()));
	}

}

(new SecurityTxtTest())->run();
