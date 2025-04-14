<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Override;
use Spaze\SecurityTxt\Fields\Contact;
use Spaze\SecurityTxt\SecurityTxt;

class ContactAddFieldValue implements FieldProcessor
{

	#[Override]
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$contact = new Contact($value);
		$securityTxt->addContact($contact);
	}

}
