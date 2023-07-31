<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

enum SecurityTxtField: string
{

	case Acknowledgments = 'Acknowledgments';
	case Canonical = 'Canonical';
	case Contact = 'Contact';
	case Expires = 'Expires';
	case PreferredLanguages = 'Preferred-Languages';

}
