<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtCanonicalNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtContactNotHttpsError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtContactNotUriSyntaxError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresTooLongWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPreferredLanguagesCommonMistakeError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPreferredLanguagesEmptyError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPreferredLanguagesWrongLanguageTagsError;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\Fields\Contact;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Fields\PreferredLanguages;
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
			'contact' => [
				[
					'https://example.com/contact' => null,
					'http://example.com/contact' => SecurityTxtContactNotHttpsError::class,
					'ftp://foo.example.net/contact.txt' => null,
					'mailto:foo@example.com' => null,
					'bar@example.com' => SecurityTxtContactNotUriSyntaxError::class,
					'tel:+1-201-555-0123' => null,
					'+1-201-555-01234' => SecurityTxtContactNotUriSyntaxError::class,
				],
				Contact::class,
				function (SecurityTxt $securityTxt): callable {
					return $securityTxt->addContact(...);
				},
				function (SecurityTxt $securityTxt): callable {
					return $securityTxt->getContact(...);
				},
				function (Contact $contact): string {
					return $contact->getUri();
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


	/**
	 * @return array<string, array{0: list<string>, 1: class-string<SecurityTxtError>}>
	 */
	public function getPreferredLanguageValues(): array
	{
		return [
			'no language' => [[], SecurityTxtPreferredLanguagesEmptyError::class],
			'empty language' => [[''], SecurityTxtPreferredLanguagesWrongLanguageTagsError::class],
			'wrong language' => [['a'], SecurityTxtPreferredLanguagesWrongLanguageTagsError::class],
			'one wrong language' => [['en', 'cs', 'E', 'CS'], SecurityTxtPreferredLanguagesWrongLanguageTagsError::class],
			'common mistake' => [['en', 'cz'], SecurityTxtPreferredLanguagesCommonMistakeError::class],
			'alright languages' => [['en', 'cs', 'EN', 'CS'], null],
		];
	}


	/**
	 * @param list<string> $languages
	 * @param class-string<SecurityTxtError>|null $exceptionClass
	 * @dataProvider getPreferredLanguageValues
	 */
	public function testSetPreferredLanguages(array $languages, ?string $exceptionClass): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxtWithInvalidValues = new SecurityTxt();
		$securityTxtWithInvalidValues->allowFieldsWithInvalidValues();

		if ($exceptionClass) {
			Assert::throws(function () use ($languages, $securityTxt, $securityTxtWithInvalidValues): void {
				$securityTxt->setPreferredLanguages(new PreferredLanguages($languages));
			}, $exceptionClass);
			Assert::throws(function () use ($languages, $securityTxt, $securityTxtWithInvalidValues): void {
				$securityTxtWithInvalidValues->setPreferredLanguages(new PreferredLanguages($languages));
			}, $exceptionClass);
		} else {
			$securityTxt->setPreferredLanguages(new PreferredLanguages($languages));
			$securityTxtWithInvalidValues->setPreferredLanguages(new PreferredLanguages($languages));
		}

		if ($exceptionClass) {
			Assert::null($securityTxt->getPreferredLanguages());
		} else {
			Assert::same($languages, $securityTxt->getPreferredLanguages()->getLanguages());
		}
		Assert::same($languages, $securityTxtWithInvalidValues->getPreferredLanguages()->getLanguages());
	}

}

(new SecurityTxtTest())->run();
