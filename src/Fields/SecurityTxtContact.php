<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Override;

final class SecurityTxtContact extends SecurityTxtUriField implements SecurityTxtFieldValue
{

	#[Override]
	public function getField(): SecurityTxtField
	{
		return SecurityTxtField::Contact;
	}


	public static function email(string $email): self
	{
		return new self('mailto:' . $email);
	}


	/**
	 * A space is not one of the visual separators a `tel:` URI allows, a hyphen is.
	 */
	public static function phone(string $phone): self
	{
		return new self('tel:' . str_replace(' ', '-', $phone));
	}

}
