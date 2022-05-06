<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\Contact;
use Throwable;

class SecurityTxtContactNotUriSyntaxError extends SecurityTxtError
{

	public function __construct(Contact $contact, ?Throwable $previous = null)
	{
		$isEmail = (bool)filter_var($contact->getUri(), FILTER_VALIDATE_EMAIL);
		parent::__construct(
			"The value doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
			'draft-foudil-securitytxt-03',
			($isEmail ? 'mailto:' : 'tel:') . $contact->getUri(),
			$isEmail ? 'The value looks like an email address, add the "mailto" schema' : 'The value looks like a phone number, add the "tel" schema',
			'2.5.3',
			previous: $previous,
		);
	}

}
