<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\SecurityTxtAcknowledgments;
use Spaze\SecurityTxt\Fields\SecurityTxtContact;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Fields\SecurityTxtPreferredLanguages;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtValidationLevel;
use Spaze\SecurityTxt\Writer\SecurityTxtWriter;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtWriterTest extends TestCase
{

	private SecurityTxtWriter $securityTxtWriter;
	private SecurityTxtExpiresFactory $securityTxtExpiresFactory;


	public function __construct()
	{
		$this->securityTxtWriter = new SecurityTxtWriter();
		$this->securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
	}


	public function testWriteEmpty(): void
	{
		$securityTxt = new SecurityTxt();
		Assert::same('', $this->securityTxtWriter->write($securityTxt));
	}


	public function testWrite(): void
	{
		$dateTime = new DateTimeImmutable('+3 months midnight');
		$securityTxt = new SecurityTxt();
		$securityTxt->addContact(new SecurityTxtContact('https://contact.example'));
		$securityTxt->addContact(SecurityTxtContact::phone('123456'));
		$securityTxt->addContact(SecurityTxtContact::email('email@com.example'));
		$securityTxt->addAcknowledgments(new SecurityTxtAcknowledgments('https://ack1.example'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create($dateTime));
		$securityTxt->addAcknowledgments(new SecurityTxtAcknowledgments('ftp://ack2.example'));
		$securityTxt->setPreferredLanguages(new SecurityTxtPreferredLanguages(['en', 'cs-CZ']));
		$expected = "Contact: https://contact.example\n"
			. "Contact: tel:123456\n"
			. "Contact: mailto:email@com.example\n"
			. "Acknowledgments: https://ack1.example\n"
			. 'Expires: ' . $dateTime->format(DATE_RFC3339) . "\n"
			. "Acknowledgments: ftp://ack2.example\n"
			. "Preferred-Languages: en,cs-CZ\n";
		Assert::same($expected, $this->securityTxtWriter->write($securityTxt));
	}


	public function testWriteDefaultValidationLevel(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->addContact(new SecurityTxtContact('https://contact.example.com'));
		Assert::throws(function () use ($securityTxt): void {
			$securityTxt->addContact(new SecurityTxtContact('//no.scheme.example'));
		}, SecurityTxtError::class, "The Contact value (//no.scheme.example) doesn't follow the URI syntax described in RFC 3986, the scheme is missing");
		Assert::same("Contact: https://contact.example.com\n", $this->securityTxtWriter->write($securityTxt));

		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::NoInvalidValues);
		$securityTxt->addContact(new SecurityTxtContact('https://contact.example.com'));
		Assert::throws(function () use ($securityTxt): void {
			$securityTxt->addContact(new SecurityTxtContact('//no.scheme.example'));
		}, SecurityTxtError::class, "The Contact value (//no.scheme.example) doesn't follow the URI syntax described in RFC 3986, the scheme is missing");
		Assert::same("Contact: https://contact.example.com\n", $this->securityTxtWriter->write($securityTxt));
	}


	public function testWriteAllowInvalidValues(): void
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValues);
		$securityTxt->addContact(new SecurityTxtContact('https://contact.example.com'));
		Assert::throws(function () use ($securityTxt): void {
			$securityTxt->addContact(new SecurityTxtContact('//no.scheme.example'));
		}, SecurityTxtError::class, "The Contact value (//no.scheme.example) doesn't follow the URI syntax described in RFC 3986, the scheme is missing");
		Assert::same("Contact: https://contact.example.com\nContact: //no.scheme.example\n", $this->securityTxtWriter->write($securityTxt));
	}


	public function testWriteAllowInvalidValuesSilently(): void
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$securityTxt->addContact(new SecurityTxtContact('https://contact.example.com'));
		$securityTxt->addContact(new SecurityTxtContact('//no.scheme.example'));
		Assert::same("Contact: https://contact.example.com\nContact: //no.scheme.example\n", $this->securityTxtWriter->write($securityTxt));
	}

}

new SecurityTxtWriterTest()->run();
