<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Override;

final class Canonical extends SecurityTxtUriField implements SecurityTxtFieldValue
{

	#[Override]
	public function getField(): SecurityTxtField
	{
		return SecurityTxtField::Canonical;
	}

}
