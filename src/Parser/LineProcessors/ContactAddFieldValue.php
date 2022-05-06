<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Fields\Contact;
use Spaze\SecurityTxt\SecurityTxt;

class ContactAddFieldValue implements LineProcessor
{

	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$contact = new Contact($value);
		$securityTxt->addContact($contact);
	}

}
