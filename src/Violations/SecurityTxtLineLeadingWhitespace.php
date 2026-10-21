<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

final class SecurityTxtLineLeadingWhitespace extends SecurityTxtSpecViolation
{

	public function __construct(string $line)
	{
		parent::__construct(
			func_get_args(),
			'The line (%s) starts with whitespace',
			[$line],
			'draft-foudil-securitytxt-00',
			ltrim($line),
			'Remove the whitespace from the start of the line',
			[],
			'4',
			['2.1'],
		);
	}

}
