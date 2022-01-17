<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

enum SecurityTxtField: string
{

	case Canonical = 'Canonical';
	case Expires = 'Expires';

}
