<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Fields\Encryption;
use Spaze\SecurityTxt\SecurityTxt;

class EncryptionAddFieldValue implements LineProcessor
{

	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$encryption = new Encryption($value);
		$securityTxt->addEncryption($encryption);
	}

}
