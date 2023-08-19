<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Fields\Encryption;
use Spaze\SecurityTxt\SecurityTxt;

class EncryptionAddFieldValue implements FieldProcessor
{

	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$encryption = new Encryption($value);
		$securityTxt->addEncryption($encryption);
	}

}
